//! `Project` — bucket and object operations.

use std::pin::Pin;
use std::sync::Arc;

use futures_core::Stream;
use futures_util::stream;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::access::Access;
use crate::bucket::require_bucket_name;
use crate::error::{Error, ErrorKind, Result};
use crate::metainfo::{MetainfoClient, object_from_proto, parse_satellite_url};
use crate::types::{
    Bucket, BucketObjectLockConfiguration, CommitUploadOptions, Config, CustomMetadata,
    DownloadOptions, ListUploadPartsOptions, ListUploadsOptions, Object, Retention,
    SetObjectRetentionOptions, SystemMetadata, UploadInfo, UploadOptions,
};
use crate::upload::{Download, FlushedSegment, PartUpload, Upload, UploadInner};

/// Stream of buckets.
pub type BucketStream = Pin<Box<dyn Stream<Item = Result<Bucket>> + Send>>;
/// Stream of objects / prefixes.
pub type ObjectStream = Pin<Box<dyn Stream<Item = Result<Object>> + Send>>;
/// Stream of uncommitted uploads.
pub type UploadStream = Pin<Box<dyn Stream<Item = Result<UploadInfo>> + Send>>;
/// Stream of multipart parts.
pub type PartStream = Pin<Box<dyn Stream<Item = Result<crate::types::Part>> + Send>>;

pub(crate) struct ProjectInner {
    pub(crate) metainfo: MetainfoClient,
    pub(crate) store: storj_encryption::Store,
    pub(crate) identity: storj_rpc::Identity,
    pub(crate) pool: storj_uplink::upload::SnPool,
    pub(crate) satellite_ca: Vec<u8>,
    pub(crate) dial_timeout: std::time::Duration,
}

/// Handle to a satellite project. `Clone` via `Arc`. `Send + Sync`.
#[derive(Clone)]
pub struct Project {
    pub(crate) inner: Arc<ProjectInner>,
}

impl Project {
    /// Open a project. 2025 `open` was infallible; native dial/TLS can fail.
    pub async fn open(access: &Access) -> Result<Self> {
        Self::open_with_config(access, Config::default()).await
    }

    /// Open with an explicit config. Dials the satellite and pins NodeID.
    pub async fn open_with_config(access: &Access, config: Config) -> Result<Self> {
        let node = parse_satellite_url(access.satellite_address())?;
        let metainfo =
            MetainfoClient::connect(node, access.api_key_raw().to_vec(), &config).await?;
        let store = store_from_grant(access.grant())?;
        let identity = metainfo.identity().clone();
        let satellite_ca = metainfo.satellite_ca().await;
        let dial_timeout = config.dial_timeout_or_default();
        Ok(Self {
            inner: Arc::new(ProjectInner {
                metainfo,
                store,
                identity,
                pool: storj_uplink::pool::ConnectionPool::new(
                    storj_uplink::pool::PoolConfig::default(),
                ),
                satellite_ca,
                dial_timeout,
            }),
        })
    }

    /// Close pooled connections. Also called on Drop (best-effort).
    pub async fn close(self) -> Result<()> {
        self.inner.metainfo.close().await;
        Ok(())
    }

    /// Start an object upload.
    pub async fn upload_object(
        &self,
        bucket: &str,
        key: &str,
        opts: UploadOptions,
    ) -> Result<Upload> {
        require_bucket_name(bucket)?;
        require_object_key(key)?;
        let enc_path =
            storj_encryption::encrypt_path(bucket, key, &self.inner.store).map_err(map_enc)?;
        let enc_params = storj_proto::encryption::EncryptionParameters {
            cipher_suite: storj_proto::encryption::CipherSuite::EncAesgcm as i32,
            block_size: crate::constants::ENCRYPTION_BLOCK_SIZE as i64,
        };
        let begin = self
            .inner
            .metainfo
            .begin_object(bucket, enc_path.clone(), opts.expires, Some(enc_params))
            .await?;
        let content_key =
            storj_encryption::derive_content_key(bucket, key.as_bytes(), &self.inner.store)
                .map_err(map_enc)?;
        let (cipher, block_size) = encryption_from_begin(&begin);
        let info = Object {
            key: key.to_owned(),
            is_prefix: false,
            system: SystemMetadata {
                created: None,
                expires: opts.expires,
                content_length: 0,
            },
            custom: CustomMetadata::new(),
        };
        Ok(Upload::new(
            info,
            UploadInner {
                project: Arc::clone(&self.inner),
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                encrypted_object_key: enc_path,
                stream_id: begin.stream_id,
                content_key,
                cipher,
                block_size,
                custom: CustomMetadata::new(),
                plaintext: Vec::new(),
                next_segment: 0,
                total_plain: 0,
                last_segment_plain: 0,
                pending_flush: None,
            },
        ))
    }

    /// Start an object download.
    pub async fn download_object(
        &self,
        bucket: &str,
        key: &str,
        opts: DownloadOptions,
    ) -> Result<Download> {
        opts.validate()?;
        require_bucket_name(bucket)?;
        require_object_key(key)?;
        let enc_path =
            storj_encryption::encrypt_path(bucket, key, &self.inner.store).map_err(map_enc)?;
        let content_key =
            storj_encryption::derive_content_key(bucket, key.as_bytes(), &self.inner.store)
                .map_err(map_enc)?;
        let range = storj_uplink::download::proto_range(opts.offset, opts.length);
        let resp = self
            .inner
            .metainfo
            .download_object(bucket, key, enc_path, range)
            .await?;
        download_segments(&self.inner, bucket, key, content_key, opts, resp).await
    }

    /// Replace custom metadata. Existing custom metadata is deleted.
    pub async fn update_object_metadata(
        &self,
        bucket: &str,
        key: &str,
        metadata: CustomMetadata,
    ) -> Result<()> {
        require_bucket_name(bucket)?;
        require_object_key(key)?;
        let enc_path =
            storj_encryption::encrypt_path(bucket, key, &self.inner.store).map_err(map_enc)?;
        let resp = self
            .inner
            .metainfo
            .get_object(bucket, key, enc_path.clone())
            .await?;
        let Some(pb) = resp.object else {
            return Err(Error::new(
                ErrorKind::ObjectNotFound,
                format!("object not found ({key:?})"),
            ));
        };
        let content_key =
            storj_encryption::derive_content_key(bucket, key.as_bytes(), &self.inner.store)
                .map_err(map_enc)?;
        let (mut cipher, mut block_size) =
            encryption_from_params(pb.encryption_parameters.as_ref());
        let (segments_size, last_segment_size, number_of_segments) =
            if pb.encrypted_metadata.is_empty() {
                (0, 0, 0)
            } else {
                let (meta, info, _) = storj_uplink::pipeline::decrypt_user_data_full(
                    &pb.encrypted_metadata,
                    &pb.encrypted_metadata_encrypted_key,
                    &pb.encrypted_metadata_nonce,
                    cipher,
                    &content_key,
                )
                .map_err(map_uplink)?;
                if meta.encryption_type != 0 {
                    cipher = storj_encryption::CipherSuite(meta.encryption_type);
                }
                if meta.encryption_block_size > 0 {
                    if let Ok(b) = usize::try_from(meta.encryption_block_size) {
                        block_size = b;
                    }
                }
                (
                    info.segments_size,
                    info.last_segment_size,
                    meta.number_of_segments,
                )
            };
        let custom_pairs: Vec<(String, String)> = metadata.into_iter().collect();
        let user = storj_uplink::pipeline::encrypt_user_data(
            &custom_pairs,
            segments_size,
            last_segment_size,
            number_of_segments,
            cipher,
            &content_key,
            block_size,
        )
        .map_err(map_uplink)?;
        self.inner
            .metainfo
            .update_object_metadata(bucket, key, enc_path, pb.stream_id, user)
            .await
    }

    /// Revoke the API key in `access`. Cannot revoke self. Satellite-cached delay possible.
    pub async fn revoke_access(&self, access: &Access) -> Result<()> {
        let raw = access.api_key_raw();
        if raw == self.inner.metainfo.api_key() {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "permission denied (API key cannot revoke itself)",
            ));
        }
        self.inner.metainfo.revoke_api_key(raw.to_vec()).await
    }

    /// Get object retention (Object Lock).
    pub async fn get_object_retention(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&[u8]>,
    ) -> Result<Option<Retention>> {
        let _ = (bucket, key, version);
        Err(Error::not_implemented("Project::get_object_retention"))
    }

    /// Set object retention (Object Lock).
    pub async fn set_object_retention(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&[u8]>,
        retention: Retention,
        opts: SetObjectRetentionOptions,
    ) -> Result<()> {
        let _ = (bucket, key, version, retention, opts);
        Err(Error::not_implemented("Project::set_object_retention"))
    }

    /// Get object legal hold.
    pub async fn get_object_legal_hold(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&[u8]>,
    ) -> Result<bool> {
        let _ = (bucket, key, version);
        Err(Error::not_implemented("Project::get_object_legal_hold"))
    }

    /// Set object legal hold.
    pub async fn set_object_legal_hold(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&[u8]>,
        enabled: bool,
    ) -> Result<()> {
        let _ = (bucket, key, version, enabled);
        Err(Error::not_implemented("Project::set_object_legal_hold"))
    }

    /// Get bucket Object Lock configuration.
    pub async fn get_bucket_object_lock_configuration(
        &self,
        bucket: &str,
    ) -> Result<BucketObjectLockConfiguration> {
        let _ = bucket;
        Err(Error::not_implemented(
            "Project::get_bucket_object_lock_configuration",
        ))
    }

    /// Set bucket Object Lock configuration.
    pub async fn set_bucket_object_lock_configuration(
        &self,
        bucket: &str,
        config: BucketObjectLockConfiguration,
    ) -> Result<()> {
        let _ = (bucket, config);
        Err(Error::not_implemented(
            "Project::set_bucket_object_lock_configuration",
        ))
    }

    /// Begin a multipart upload.
    pub async fn begin_upload(
        &self,
        bucket: &str,
        key: &str,
        opts: UploadOptions,
    ) -> Result<UploadInfo> {
        let _ = (bucket, key, opts);
        Err(Error::not_implemented("Project::begin_upload"))
    }

    /// Upload one part of a multipart upload.
    pub async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: u32,
    ) -> Result<PartUpload> {
        let _ = (bucket, key, upload_id, part_number);
        Err(Error::not_implemented("Project::upload_part"))
    }

    /// Commit a multipart upload.
    pub async fn commit_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        opts: CommitUploadOptions,
    ) -> Result<Object> {
        let _ = (bucket, key, upload_id, opts);
        Err(Error::not_implemented("Project::commit_upload"))
    }

    /// Abort a multipart upload.
    pub async fn abort_upload(&self, bucket: &str, key: &str, upload_id: &str) -> Result<()> {
        let _ = (bucket, key, upload_id);
        Err(Error::not_implemented("Project::abort_upload"))
    }

    /// List uncommitted uploads.
    pub fn list_uploads(&self, bucket: &str, opts: ListUploadsOptions) -> UploadStream {
        let _ = bucket;
        if let Err(e) = opts.validate() {
            return Box::pin(stream::once(async move { Err(e) }));
        }
        Box::pin(stream::once(async {
            Err(Error::not_implemented("Project::list_uploads"))
        }))
    }

    /// List parts of a multipart upload.
    pub fn list_upload_parts(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        opts: ListUploadPartsOptions,
    ) -> PartStream {
        let _ = (bucket, key, upload_id, opts);
        Box::pin(stream::once(async {
            Err(Error::not_implemented("Project::list_upload_parts"))
        }))
    }

    /// `AsyncRead` → object. Commits on success, aborts on error.
    pub async fn upload_from(
        &self,
        bucket: &str,
        key: &str,
        reader: impl AsyncRead + Send,
        opts: UploadOptions,
    ) -> Result<Object> {
        let mut upload = self.upload_object(bucket, key, opts).await?;
        let mut reader = std::pin::pin!(reader);
        match tokio::io::copy(&mut reader, &mut upload).await {
            Ok(_) => upload.commit().await,
            Err(e) => {
                let _ = upload.abort().await;
                Err(e.into())
            }
        }
    }

    /// Object → `AsyncWrite`.
    pub async fn download_to(
        &self,
        bucket: &str,
        key: &str,
        writer: impl AsyncWrite + Send,
        opts: DownloadOptions,
    ) -> Result<Object> {
        let mut download = self.download_object(bucket, key, opts).await?;
        let info = download.info().clone();
        let mut writer = std::pin::pin!(writer);
        let copy = tokio::io::copy(&mut download, &mut writer).await;
        let flush = writer.flush().await;
        let close = download.close().await;
        copy?;
        flush?;
        close?;
        Ok(info)
    }
}

pub(crate) fn require_object_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(Error::new(
            ErrorKind::ObjectKeyInvalid,
            r#"object key invalid ("")"#,
        ));
    }
    Ok(())
}

pub(crate) fn map_enc(e: storj_encryption::Error) -> Error {
    let kind = match e.kind() {
        storj_encryption::ErrorKind::DecryptionFailed => ErrorKind::DecryptionFailed,
        storj_encryption::ErrorKind::MissingEncryptionBase
        | storj_encryption::ErrorKind::MissingDecryptionBase => ErrorKind::InvalidGrant,
        _ => ErrorKind::Protocol,
    };
    Error::new(kind, e.to_string()).with_source(e)
}

fn map_cipher(c: storj_access::CipherSuite) -> storj_encryption::CipherSuite {
    if c.0 == 0 {
        storj_encryption::CipherSuite::AES_GCM
    } else {
        storj_encryption::CipherSuite(c.0)
    }
}

fn store_from_grant(grant: &storj_access::Grant) -> Result<storj_encryption::Store> {
    let enc = grant.enc_access();
    let mut store = storj_encryption::Store::new();
    store.set_default_path_cipher(map_cipher(enc.default_path_cipher));
    if let Some(k) = enc.default_key {
        store.set_default_key(storj_encryption::Key::from_bytes(k));
    }
    for e in &enc.store_entries {
        let bucket = String::from_utf8_lossy(&e.bucket);
        store
            .add_with_cipher(
                &bucket,
                &e.unencrypted_path,
                &e.encrypted_path,
                storj_encryption::Key::from_bytes(e.key),
                map_cipher(e.path_cipher),
            )
            .map_err(map_enc)?;
    }
    Ok(store)
}

fn encryption_from_begin(
    begin: &storj_proto::metainfo::BeginObjectResponse,
) -> (storj_encryption::CipherSuite, usize) {
    encryption_from_params(begin.encryption_parameters.as_ref())
}

pub(crate) fn encryption_from_params(
    params: Option<&storj_proto::encryption::EncryptionParameters>,
) -> (storj_encryption::CipherSuite, usize) {
    let cipher = match params.map(|p| p.cipher_suite) {
        Some(2) | Some(0) | None => storj_encryption::CipherSuite::AES_GCM,
        Some(1) => storj_encryption::CipherSuite::NULL,
        Some(3) => storj_encryption::CipherSuite::SECRET_BOX,
        Some(v) => storj_encryption::CipherSuite(v),
    };
    let block = params
        .map(|p| p.block_size)
        .filter(|&b| b > 0)
        .and_then(|b| usize::try_from(b).ok())
        .unwrap_or(crate::constants::ENCRYPTION_BLOCK_SIZE);
    (cipher, block)
}

pub(crate) fn map_uplink(e: storj_uplink::Error) -> Error {
    match e {
        storj_uplink::Error::Encryption(enc) => map_enc(enc),
        other => Error::new(ErrorKind::Protocol, other.to_string()).with_source(other),
    }
}

async fn download_segments(
    project: &ProjectInner,
    bucket: &str,
    key: &str,
    content_key: storj_encryption::Key,
    opts: DownloadOptions,
    resp: storj_proto::metainfo::DownloadObjectResponse,
) -> Result<Download> {
    use storj_uplink::download::{proto_range, resolve_range, segment_plain_range};
    use storj_uplink::pipeline::decrypt_user_data;

    let stream_id = resp
        .object
        .as_ref()
        .map(|o| o.stream_id.clone())
        .unwrap_or_default();
    let mut info = object_from_proto(resp.object.clone(), key);
    let (mut cipher, mut block_size) = encryption_from_params(
        resp.object
            .as_ref()
            .and_then(|o| o.encryption_parameters.as_ref()),
    );
    if let Some(obj) = &resp.object {
        if !obj.encrypted_metadata.is_empty() {
            let (meta, custom) = decrypt_user_data(
                &obj.encrypted_metadata,
                &obj.encrypted_metadata_encrypted_key,
                &obj.encrypted_metadata_nonce,
                cipher,
                &content_key,
            )
            .map_err(map_uplink)?;
            if meta.encryption_type != 0 {
                cipher = storj_encryption::CipherSuite(meta.encryption_type);
            }
            if meta.encryption_block_size > 0 {
                if let Ok(b) = usize::try_from(meta.encryption_block_size) {
                    block_size = b;
                }
            }
            info.custom = custom.user_defined.into_iter().collect();
        }
    }

    let mut list = resp.segment_list.unwrap_or_default();
    let mut downloaded = resp.segment_download;
    let list_range = proto_range(opts.offset, opts.length);
    while list.more {
        let cursor = list.items.last().and_then(|i| i.position);
        let page = project
            .metainfo
            .list_segments(bucket, key, stream_id.clone(), cursor, list_range)
            .await?;
        if page.items.is_empty() {
            break;
        }
        list.more = page.more;
        list.items.extend(page.items);
    }
    if info.system.content_length <= 0 {
        let listed: i64 = list.items.iter().map(|i| i.plain_size).sum();
        if listed > 0 {
            info.system.content_length = listed;
        } else {
            info.system.content_length = downloaded.iter().map(|s| s.plain_size).sum();
        }
    }

    let object_size = info.system.content_length;
    let (plain_start, plain_len) =
        resolve_range(opts.offset, opts.length, object_size).map_err(map_uplink)?;
    if plain_len == 0 {
        return Ok(Download::new(info, Vec::new()));
    }

    let have: std::collections::HashSet<(i32, i32)> = downloaded
        .iter()
        .filter_map(|s| s.position.map(|p| (p.part_number, p.index)))
        .collect();
    for item in &list.items {
        let pos = item.position.unwrap_or_default();
        let (_local_start, local_len) =
            segment_plain_range(plain_start, plain_len, item.plain_offset, item.plain_size);
        if local_len == 0 || have.contains(&(pos.part_number, pos.index)) {
            continue;
        }
        downloaded.push(
            project
                .metainfo
                .download_segment(bucket, key, stream_id.clone(), pos)
                .await?,
        );
    }
    if downloaded.is_empty() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DownloadObject missing segment",
        ));
    }
    downloaded.sort_by_key(|s| {
        s.position
            .map(|p| (p.part_number, p.index))
            .unwrap_or_default()
    });

    let mut plaintext = Vec::new();
    for seg in downloaded {
        plaintext.extend(
            decrypt_one_segment(
                project,
                &content_key,
                cipher,
                block_size,
                plain_start,
                plain_len,
                seg,
            )
            .await?,
        );
    }
    let want = usize::try_from(plain_len).unwrap_or(usize::MAX);
    if plaintext.len() != want {
        return Err(Error::new(
            ErrorKind::Protocol,
            "download missing segment data",
        ));
    }
    Ok(Download::new(info, plaintext))
}

async fn decrypt_one_segment(
    project: &ProjectInner,
    content_key: &storj_encryption::Key,
    cipher: storj_encryption::CipherSuite,
    block_size: usize,
    object_start: i64,
    object_len: i64,
    seg: storj_proto::metainfo::DownloadSegmentResponse,
) -> Result<Vec<u8>> {
    use storj_uplink::download::{
        LongTailDownload, RemoteDecrypt, decode_encrypted, decrypt_inline, decrypt_remote,
        download_pieces_long_tail, piece_byte_range, segment_plain_range,
    };
    use storj_uplink::orders::PiecePrivateKey;
    use storj_uplink::pipeline::{Redundancy, content_nonce, decrypt_key, nonce_from_slice};
    use storj_uplink::segment::PieceAssignment;

    let (local_start, local_len) =
        segment_plain_range(object_start, object_len, seg.plain_offset, seg.plain_size);
    if local_len == 0 {
        return Ok(Vec::new());
    }
    let position = seg.position.unwrap_or_default();
    let nonce = content_nonce(position.part_number, position.index);
    let enc_nonce = nonce_from_slice(&seg.encrypted_key_nonce).map_err(map_uplink)?;
    let segment_key =
        decrypt_key(&seg.encrypted_key, cipher, content_key, &enc_nonce).map_err(map_uplink)?;

    if !seg.encrypted_inline_data.is_empty() || seg.addressed_limits.is_empty() {
        let full = decrypt_inline(&seg.encrypted_inline_data, cipher, &segment_key, &nonce)
            .map_err(map_uplink)?;
        return Ok(slice_plain(&full, local_start, local_len));
    }
    let scheme = seg
        .redundancy_scheme
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "download response missing RS scheme"))?;
    let rs = Redundancy::from_scheme(scheme).map_err(map_uplink)?;
    let decrypter = storj_encryption::new_decrypter(cipher, &segment_key, &nonce, block_size)
        .map_err(map_enc)?;
    let (piece_off, piece_size) = piece_byte_range(
        local_start,
        local_len,
        decrypter.out_block_size(),
        decrypter.in_block_size(),
        &rs,
    );
    let mut assignments = Vec::new();
    for (i, addressed) in seg.addressed_limits.into_iter().enumerate() {
        if addressed.limit.is_none() {
            continue;
        }
        assignments.push(PieceAssignment::from_addressed(i, addressed).map_err(map_uplink)?);
    }
    let piece_key = PiecePrivateKey::from_bytes(&seg.private_key).map_err(map_uplink)?;
    let shares = download_pieces_long_tail(LongTailDownload {
        assignments,
        piece_key,
        satellite_ca: project.satellite_ca.clone(),
        identity: project.identity.clone(),
        pool: project.pool.clone(),
        rs,
        offset: piece_off,
        size: piece_size,
        dial_timeout: project.dial_timeout,
    })
    .await
    .map_err(map_uplink)?;
    let decoded = decode_encrypted(&shares, &rs).map_err(map_uplink)?;
    let decoded_offset = usize::try_from(piece_off.saturating_mul(rs.k as i64)).unwrap_or(0);
    let encrypted_size = usize::try_from(seg.segment_size.max(0)).unwrap_or(0);
    decrypt_remote(RemoteDecrypt {
        decoded: &decoded,
        decoded_offset,
        encrypted_size,
        cipher,
        key: &segment_key,
        nonce: &nonce,
        encrypted_block_size: block_size,
        plain_start: local_start,
        plain_len: local_len,
        plain_size: seg.plain_size,
    })
    .map_err(map_uplink)
}

fn slice_plain(full: &[u8], start: i64, len: i64) -> Vec<u8> {
    if len <= 0 {
        return Vec::new();
    }
    let start = usize::try_from(start).unwrap_or(0).min(full.len());
    let end = start
        .saturating_add(usize::try_from(len).unwrap_or(0))
        .min(full.len());
    full[start..end].to_vec()
}

pub(crate) fn spawn_flush_segment(inner: &mut UploadInner) {
    const MAX: usize = crate::constants::MAX_SEGMENT_SIZE as usize;
    if inner.pending_flush.is_some() || inner.plaintext.len() < MAX {
        return;
    }
    let mut chunk = std::mem::take(&mut inner.plaintext);
    if chunk.len() > MAX {
        inner.plaintext = chunk.split_off(MAX);
    }
    let job = SegmentCommit {
        project: Arc::clone(&inner.project),
        bucket: inner.bucket.clone(),
        key: inner.key.clone(),
        stream_id: inner.stream_id.clone(),
        content_key: inner.content_key.clone(),
        cipher: inner.cipher,
        block_size: inner.block_size,
        index: inner.next_segment,
        plain: chunk,
    };
    inner.pending_flush = Some(tokio::spawn(async move {
        let index = job.index;
        let plain_size = commit_one_segment(job).await?;
        Ok(FlushedSegment { index, plain_size })
    }));
}

struct SegmentCommit {
    project: Arc<ProjectInner>,
    bucket: String,
    key: String,
    stream_id: Vec<u8>,
    content_key: storj_encryption::Key,
    cipher: storj_encryption::CipherSuite,
    block_size: usize,
    index: i32,
    plain: Vec<u8>,
}

pub(crate) async fn commit_upload(mut inner: UploadInner) -> Result<Object> {
    use storj_uplink::pipeline::encrypt_user_data;

    let abort = PendingAbort {
        project: Arc::clone(&inner.project),
        bucket: inner.bucket.clone(),
        encrypted_object_key: inner.encrypted_object_key.clone(),
        stream_id: inner.stream_id.clone(),
    };
    let mut abort_on_drop = AbortOnDrop(Some(abort));

    if let Some(handle) = inner.pending_flush.take() {
        let flushed = handle.await??;
        inner.apply_flush(flushed);
    }
    if !inner.plaintext.is_empty() || inner.next_segment == 0 {
        let job = SegmentCommit {
            project: Arc::clone(&inner.project),
            bucket: inner.bucket.clone(),
            key: inner.key.clone(),
            stream_id: inner.stream_id.clone(),
            content_key: inner.content_key.clone(),
            cipher: inner.cipher,
            block_size: inner.block_size,
            index: inner.next_segment,
            plain: std::mem::take(&mut inner.plaintext),
        };
        let index = job.index;
        let plain_size = commit_one_segment(job).await?;
        inner.apply_flush(FlushedSegment { index, plain_size });
    }

    let custom_pairs: Vec<(String, String)> = inner.custom.into_iter().collect();
    let user = encrypt_user_data(
        &custom_pairs,
        crate::constants::MAX_SEGMENT_SIZE as i64,
        inner.last_segment_plain,
        i64::from(inner.next_segment),
        inner.cipher,
        &inner.content_key,
        inner.block_size,
    )
    .map_err(map_uplink)?;

    let committed = inner
        .project
        .metainfo
        .commit_object(&inner.bucket, &inner.key, inner.stream_id, user)
        .await?;
    abort_on_drop.disarm();
    let mut obj = object_from_proto(committed.object, &inner.key);
    obj.system.content_length = inner.total_plain;
    obj.custom = custom_pairs.into_iter().collect();
    Ok(obj)
}

async fn commit_one_segment(job: SegmentCommit) -> Result<i64> {
    use storj_proto::metainfo::{CommitSegmentRequest, MakeInlineSegmentRequest, SegmentPosition};
    use storj_uplink::orders::PiecePrivateKey;
    use storj_uplink::pipeline::{
        MAX_INLINE_SEGMENT_SIZE, Redundancy, content_nonce, encode_pieces, encrypt_inline,
        encrypt_key, encrypt_remote, is_inline, random_key, random_nonce,
    };
    use storj_uplink::segment::{LongTailUpload, PieceAssignment, upload_pieces_long_tail};

    let SegmentCommit {
        project,
        bucket,
        key,
        stream_id,
        content_key,
        cipher,
        block_size,
        index,
        plain,
    } = job;
    let segment_key = random_key();
    let encrypted_key_nonce = random_nonce();
    let encrypted_key = encrypt_key(&segment_key, cipher, &content_key, &encrypted_key_nonce)
        .map_err(map_uplink)?;
    let nonce = content_nonce(0, index);
    let position = SegmentPosition {
        part_number: 0,
        index,
    };
    let last_plain = i64::try_from(plain.len()).unwrap_or(i64::MAX);

    let inline_data = if plain.len() > MAX_INLINE_SEGMENT_SIZE {
        None
    } else {
        let data = encrypt_inline(&plain, cipher, &segment_key, &nonce).map_err(map_uplink)?;
        if is_inline(&data) { Some(data) } else { None }
    };
    if let Some(inline_data) = inline_data {
        project
            .metainfo
            .make_inline_segment(
                &bucket,
                &key,
                MakeInlineSegmentRequest {
                    stream_id,
                    position: Some(position),
                    encrypted_key_nonce: encrypted_key_nonce.to_vec(),
                    encrypted_key,
                    encrypted_inline_data: inline_data,
                    plain_size: last_plain,
                    ..Default::default()
                },
            )
            .await?;
        return Ok(last_plain);
    }

    let encrypted = tokio::task::spawn_blocking(move || {
        encrypt_remote(&plain, cipher, &segment_key, &nonce, block_size)
    })
    .await?
    .map_err(map_uplink)?;
    let enc_size = i64::try_from(encrypted.len()).unwrap_or(i64::MAX);
    let begin = project
        .metainfo
        .begin_segment(&bucket, &key, stream_id, position, enc_size)
        .await?;
    let scheme = begin
        .redundancy_scheme
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "BeginSegment missing RS scheme"))?;
    let rs = Redundancy::from_scheme(scheme).map_err(map_uplink)?;
    let pieces = tokio::task::spawn_blocking(move || encode_pieces(&encrypted, &rs))
        .await?
        .map_err(map_uplink)?;
    let mut assignments = Vec::new();
    for (i, addressed) in begin.addressed_limits.into_iter().enumerate() {
        assignments.push(PieceAssignment::from_addressed(i, addressed).map_err(map_uplink)?);
    }
    let piece_key = PiecePrivateKey::from_bytes(&begin.private_key).map_err(map_uplink)?;
    let metainfo = &project.metainfo;
    let bucket_c = bucket.clone();
    let key_c = key.clone();
    let (segment_id, results) = upload_pieces_long_tail(
        LongTailUpload {
            assignments,
            segment_id: begin.segment_id.clone(),
            piece_key,
            pieces,
            satellite_ca: project.satellite_ca.clone(),
            identity: project.identity.clone(),
            pool: project.pool.clone(),
            rs,
            cohort: begin.cohort_requirements.clone(),
            dial_timeout: project.dial_timeout,
        },
        |seg_id, nums| {
            let bucket = bucket_c.clone();
            let key = key_c.clone();
            async move {
                let resp = metainfo
                    .retry_begin_segment_pieces(&bucket, &key, seg_id, nums)
                    .await
                    .map_err(|e| storj_uplink::Error::Protocol(e.to_string()))?;
                Ok((resp.segment_id, resp.addressed_limits))
            }
        },
    )
    .await
    .map_err(map_uplink)?;

    project
        .metainfo
        .commit_segment(
            &bucket,
            &key,
            CommitSegmentRequest {
                segment_id,
                encrypted_key_nonce: encrypted_key_nonce.to_vec(),
                encrypted_key,
                size_encrypted_data: enc_size,
                plain_size: last_plain,
                upload_result: results,
                ..Default::default()
            },
        )
        .await?;
    Ok(last_plain)
}

struct PendingAbort {
    project: Arc<ProjectInner>,
    bucket: String,
    encrypted_object_key: Vec<u8>,
    stream_id: Vec<u8>,
}

struct AbortOnDrop(Option<PendingAbort>);

impl AbortOnDrop {
    fn disarm(&mut self) {
        self.0.take();
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        let Some(pending) = self.0.take() else {
            return;
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = abort_pending(pending).await;
            });
        }
    }
}

async fn abort_pending(pending: PendingAbort) -> Result<()> {
    abort_upload(UploadInner {
        project: pending.project,
        bucket: pending.bucket,
        key: String::new(),
        encrypted_object_key: pending.encrypted_object_key,
        stream_id: pending.stream_id,
        content_key: storj_encryption::Key::from_bytes([0u8; 32]),
        cipher: storj_encryption::CipherSuite::AES_GCM,
        block_size: 0,
        custom: CustomMetadata::new(),
        plaintext: Vec::new(),
        next_segment: 0,
        total_plain: 0,
        last_segment_plain: 0,
        pending_flush: None,
    })
    .await
}

pub(crate) async fn abort_upload(inner: UploadInner) -> Result<()> {
    let UploadInner {
        project,
        bucket,
        encrypted_object_key,
        stream_id,
        pending_flush,
        ..
    } = inner;
    if let Some(handle) = pending_flush {
        handle.abort();
        let _ = handle.await;
    }
    let _ = project
        .metainfo
        .begin_delete_object(
            &bucket,
            encrypted_object_key,
            stream_id.clone(),
            storj_proto::metainfo::object::Status::Uploading as i32,
        )
        .await?;
    project
        .metainfo
        .finish_delete_object(&bucket, stream_id)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use tokio::io::sink;

    fn placeholder() -> Project {
        // Disconnected client for methods that must fail without dialing.
        Project {
            inner: Arc::new(ProjectInner {
                metainfo: placeholder_metainfo(),
                store: storj_encryption::Store::new(),
                identity: storj_rpc::Identity::generate().expect("ephemeral identity"),
                pool: storj_uplink::pool::ConnectionPool::new(
                    storj_uplink::pool::PoolConfig::for_redundancy_n(4),
                ),
                satellite_ca: Vec::new(),
                dial_timeout: std::time::Duration::from_secs(1),
            }),
        }
    }

    fn placeholder_metainfo() -> MetainfoClient {
        MetainfoClient::disconnected_placeholder()
    }

    #[tokio::test]
    async fn download_to_rejects_go_unsupported_combo() {
        let e = placeholder()
            .download_to(
                "b",
                "k",
                sink(),
                DownloadOptions {
                    offset: -10,
                    length: 100,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ObjectKeyInvalid);
        let e = placeholder()
            .download_to(
                "b",
                "k",
                sink(),
                DownloadOptions {
                    offset: -10,
                    length: 0,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ObjectKeyInvalid);
    }
}
