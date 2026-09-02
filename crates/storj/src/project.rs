//! `Project` — bucket and object operations.

use std::pin::Pin;
use std::sync::Arc;

use futures_core::Stream;
use futures_util::stream;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::access::Access;
use crate::bucket::require_bucket_name;
use crate::error::{Error, ErrorKind, Result};
use crate::metainfo::{MetainfoClient, object_from_proto, parse_satellite_url};
use crate::types::{
    Bucket, BucketObjectLockConfiguration, CommitUploadOptions, Config, CustomMetadata,
    DownloadOptions, ListObjectsOptions, ListUploadPartsOptions, ListUploadsOptions, Object,
    Retention, SetObjectRetentionOptions, SystemMetadata, UploadInfo, UploadOptions,
};
use crate::upload::{Download, PartUpload, Upload, UploadInner};

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
        let _ = (bucket, key);
        Err(Error::not_implemented("Project::download_object"))
    }

    /// Object metadata.
    pub async fn stat_object(&self, bucket: &str, key: &str) -> Result<Object> {
        let _ = (bucket, key);
        Err(Error::not_implemented("Project::stat_object"))
    }

    /// Delete an object.
    ///
    /// `Ok(Some(obj))` = deleted and metadata visible;
    /// `Ok(None)` = deleted (or no-op) without metadata;
    /// `Err(ObjectNotFound)` only when the satellite reports not found *and*
    /// the grant can observe that.
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<Option<Object>> {
        let _ = (bucket, key);
        Err(Error::not_implemented("Project::delete_object"))
    }

    /// List objects. `opts.prefix` must be empty or end with `/`.
    pub fn list_objects(&self, bucket: &str, opts: ListObjectsOptions) -> ObjectStream {
        let _ = bucket;
        if let Err(e) = opts.validate() {
            return Box::pin(stream::once(async move { Err(e) }));
        }
        Box::pin(stream::once(async {
            Err(Error::not_implemented("Project::list_objects"))
        }))
    }

    /// Atomic copy without downloading.
    pub async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> Result<Object> {
        let _ = (src_bucket, src_key, dst_bucket, dst_key);
        Err(Error::not_implemented("Project::copy_object"))
    }

    /// Move (server-side rename).
    pub async fn move_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> Result<()> {
        let _ = (src_bucket, src_key, dst_bucket, dst_key);
        Err(Error::not_implemented("Project::move_object"))
    }

    /// Replace custom metadata. Existing custom metadata is deleted.
    pub async fn update_object_metadata(
        &self,
        bucket: &str,
        key: &str,
        metadata: CustomMetadata,
    ) -> Result<()> {
        let _ = (bucket, key, metadata);
        Err(Error::not_implemented("Project::update_object_metadata"))
    }

    /// Revoke the API key in `access`. Cannot revoke self.
    pub async fn revoke_access(&self, access: &Access) -> Result<()> {
        let _ = access;
        Err(Error::not_implemented("Project::revoke_access"))
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
        let _ = (bucket, key, reader, opts);
        Err(Error::not_implemented("Project::upload_from"))
    }

    /// Object → `AsyncWrite`.
    pub async fn download_to(
        &self,
        bucket: &str,
        key: &str,
        writer: impl AsyncWrite + Send,
        opts: DownloadOptions,
    ) -> Result<Object> {
        opts.validate()?;
        let _ = (bucket, key, writer);
        Err(Error::not_implemented("Project::download_to"))
    }
}

fn require_object_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(Error::new(
            ErrorKind::ObjectKeyInvalid,
            r#"object key invalid ("")"#,
        ));
    }
    Ok(())
}

fn map_enc(e: storj_encryption::Error) -> Error {
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
    let params = begin.encryption_parameters.as_ref();
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

pub(crate) async fn commit_upload(inner: UploadInner) -> Result<Object> {
    use storj_proto::metainfo::{CommitSegmentRequest, MakeInlineSegmentRequest, SegmentPosition};
    use storj_uplink::orders::PiecePrivateKey;
    use storj_uplink::pipeline::content_nonce;
    use storj_uplink::pipeline::{
        Redundancy, encode_pieces, encrypt_inline, encrypt_key, encrypt_remote, encrypt_user_data,
        is_inline, random_key, random_nonce,
    };
    use storj_uplink::segment::{LongTailUpload, PieceAssignment, upload_pieces_long_tail};

    let abort = PendingAbort {
        project: Arc::clone(&inner.project),
        bucket: inner.bucket.clone(),
        encrypted_object_key: inner.encrypted_object_key.clone(),
        stream_id: inner.stream_id.clone(),
    };
    let mut abort_on_drop = AbortOnDrop(Some(abort));

    let UploadInner {
        project,
        bucket,
        key,
        encrypted_object_key: _,
        stream_id,
        content_key,
        cipher,
        block_size,
        custom,
        plaintext,
    } = inner;

    let segment_key = random_key();
    let encrypted_key_nonce = random_nonce();
    let encrypted_key = encrypt_key(&segment_key, cipher, &content_key, &encrypted_key_nonce)
        .map_err(|e| Error::new(ErrorKind::Protocol, e.to_string()).with_source(e))?;
    let nonce = content_nonce(0, 0);
    let inline_data = encrypt_inline(&plaintext, cipher, &segment_key, &nonce)
        .map_err(|e| Error::new(ErrorKind::Protocol, e.to_string()).with_source(e))?;
    let position = SegmentPosition {
        part_number: 0,
        index: 0,
    };
    let last_plain = i64::try_from(plaintext.len()).unwrap_or(i64::MAX);

    if is_inline(&inline_data) {
        project
            .metainfo
            .make_inline_segment(
                &bucket,
                &key,
                MakeInlineSegmentRequest {
                    stream_id: stream_id.clone(),
                    position: Some(position),
                    encrypted_key_nonce: encrypted_key_nonce.to_vec(),
                    encrypted_key: encrypted_key.clone(),
                    encrypted_inline_data: inline_data,
                    plain_size: last_plain,
                    ..Default::default()
                },
            )
            .await?;
    } else {
        let encrypted = encrypt_remote(&plaintext, cipher, &segment_key, &nonce, block_size)
            .map_err(|e| Error::new(ErrorKind::Protocol, e.to_string()).with_source(e))?;
        let enc_size = i64::try_from(encrypted.len()).unwrap_or(i64::MAX);
        let begin = project
            .metainfo
            .begin_segment(&bucket, &key, stream_id.clone(), position, enc_size)
            .await?;
        let scheme = begin
            .redundancy_scheme
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "BeginSegment missing RS scheme"))?;
        let rs = Redundancy::from_scheme(scheme)
            .map_err(|e| Error::new(ErrorKind::Protocol, e.to_string()).with_source(e))?;
        let pieces = encode_pieces(&encrypted, &rs)
            .map_err(|e| Error::new(ErrorKind::Protocol, e.to_string()).with_source(e))?;
        let mut assignments = Vec::new();
        for (i, addressed) in begin.addressed_limits.into_iter().enumerate() {
            assignments.push(
                PieceAssignment::from_addressed(i, addressed)
                    .map_err(|e| Error::new(ErrorKind::Protocol, e.to_string()).with_source(e))?,
            );
        }
        let piece_key = PiecePrivateKey::from_bytes(&begin.private_key)
            .map_err(|e| Error::new(ErrorKind::Protocol, e.to_string()).with_source(e))?;
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
        .map_err(|e| Error::new(ErrorKind::Protocol, e.to_string()).with_source(e))?;

        project
            .metainfo
            .commit_segment(
                &bucket,
                &key,
                CommitSegmentRequest {
                    segment_id,
                    encrypted_key_nonce: encrypted_key_nonce.to_vec(),
                    encrypted_key: encrypted_key.clone(),
                    size_encrypted_data: enc_size,
                    plain_size: last_plain,
                    upload_result: results,
                    ..Default::default()
                },
            )
            .await?;
    }

    let custom_pairs: Vec<(String, String)> = custom.into_iter().collect();
    let user = encrypt_user_data(
        &custom_pairs,
        crate::constants::MAX_SEGMENT_SIZE as i64,
        last_plain,
        cipher,
        &content_key,
        block_size,
    )
    .map_err(|e| Error::new(ErrorKind::Protocol, e.to_string()).with_source(e))?;

    let committed = project
        .metainfo
        .commit_object(&bucket, &key, stream_id, user)
        .await?;
    abort_on_drop.disarm();
    let mut obj = object_from_proto(committed.object, &key);
    obj.system.content_length = last_plain;
    obj.custom = custom_pairs.into_iter().collect();
    Ok(obj)
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
    })
    .await
}

pub(crate) async fn abort_upload(inner: UploadInner) -> Result<()> {
    let _ = inner
        .project
        .metainfo
        .begin_delete_object(
            &inner.bucket,
            inner.encrypted_object_key,
            inner.stream_id.clone(),
        )
        .await?;
    inner
        .project
        .metainfo
        .finish_delete_object(&inner.bucket, inner.stream_id)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use tokio::io::{empty, sink};

    fn placeholder() -> Project {
        // Object helpers are still stubs; they must not dial.
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
    async fn upload_from_not_implemented() {
        let e = placeholder()
            .upload_from("b", "k", empty(), UploadOptions::default())
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
        assert!(e.to_string().contains("not implemented"));
    }

    #[tokio::test]
    async fn download_to_not_implemented() {
        let e = placeholder()
            .download_to("b", "k", sink(), DownloadOptions::default())
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
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
    }
}
