//! Object metadata, listing, copy, and move.

use std::collections::VecDeque;

use futures_util::stream;
use storj_encryption::{
    CipherSuite, Key, PathIter, decrypt_iterator, derive_content_key, derive_path_key,
    encrypt_iterator, encrypt_path,
};
use storj_proto::metainfo::{
    EncryptedKeyAndNonce, FinishCopyObjectRequest, FinishMoveObjectRequest, ObjectListItem,
    object::Status as ObjectStatus,
};
use storj_uplink::pipeline::{
    decrypt_key, decrypt_user_data, encrypt_key, nonce_from_slice, random_nonce,
};

use crate::bucket::require_bucket_name;
use crate::error::{Error, ErrorKind, Result};
use crate::metainfo::object_from_proto;
use crate::project::{
    ObjectStream, Project, encryption_from_params, map_enc, map_uplink, require_object_key,
};
use crate::types::{CustomMetadata, ListObjectsOptions, Object, SystemMetadata};

impl Project {
    /// Object metadata. Uses GetObject (no piece download).
    pub async fn stat_object(&self, bucket: &str, key: &str) -> Result<Object> {
        require_bucket_name(bucket)?;
        require_object_key(key)?;
        let enc_path = encrypt_path(bucket, key, &self.inner.store).map_err(map_enc)?;
        let resp = self
            .inner
            .metainfo
            .get_object(bucket, key, enc_path)
            .await?;
        let Some(pb) = resp.object else {
            return Err(Error::new(
                ErrorKind::Protocol,
                "GetObject returned no object",
            ));
        };
        object_from_info(pb, bucket, key, false, true, true, &self.inner.store)
    }

    /// Delete an object.
    ///
    /// `Ok(Some(obj))` = deleted and metadata visible;
    /// `Ok(None)` = deleted (or no-op) without metadata;
    /// `Err(ObjectNotFound)` only when the satellite reports not found *and*
    /// the grant can observe that.
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<Option<Object>> {
        require_bucket_name(bucket)?;
        require_object_key(key)?;
        let enc_path = encrypt_path(bucket, key, &self.inner.store).map_err(map_enc)?;
        let resp = self
            .inner
            .metainfo
            .begin_delete_object(bucket, enc_path, Vec::new(), 0)
            .await?;
        let Some(pb) = resp.object else {
            return Ok(None);
        };
        if pb.bucket.is_empty() {
            return Ok(None);
        }
        Ok(Some(object_from_info(
            pb,
            bucket,
            key,
            false,
            true,
            true,
            &self.inner.store,
        )?))
    }

    /// List objects. `opts.prefix` must be empty or end with `/`.
    pub fn list_objects(&self, bucket: &str, opts: ListObjectsOptions) -> ObjectStream {
        if let Err(e) = opts.validate() {
            return Box::pin(stream::once(async move { Err(e) }));
        }
        if let Err(e) = require_bucket_name(bucket) {
            return Box::pin(stream::once(async move { Err(e) }));
        }
        match prepare_list(self, bucket, &opts) {
            Err(e) => Box::pin(stream::once(async move { Err(e) })),
            Ok(st) => Box::pin(stream::try_unfold(st, |mut st| async move {
                loop {
                    if let Some(obj) = st.pending.pop_front() {
                        return Ok(Some((obj, st)));
                    }
                    if st.done {
                        return Ok(None);
                    }
                    let page = st
                        .project
                        .inner
                        .metainfo
                        .list_objects(
                            &st.bucket,
                            crate::metainfo::ListObjectsParams {
                                encrypted_prefix: st.encrypted_prefix.clone(),
                                encrypted_cursor: st.encrypted_cursor.clone(),
                                recursive: st.recursive,
                                include_custom: st.custom,
                                include_system: st.system,
                                arbitrary_prefix: st.arbitrary_prefix,
                            },
                        )
                        .await?;
                    if let Some(last) = page.items.last() {
                        st.encrypted_cursor = last.encrypted_object_key.clone();
                    }
                    st.done = !page.more || page.items.is_empty();
                    let converted = convert_list_page(&st, page.items)?;
                    if converted.is_empty() && !st.done {
                        continue;
                    }
                    st.pending.extend(converted);
                }
            })),
        }
    }

    /// Atomic copy without downloading.
    pub async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> Result<Object> {
        let (src_enc, dst_enc, old_content, new_content) =
            prepare_copy_move(self, src_bucket, src_key, dst_bucket, dst_key)?;
        let begin = self
            .inner
            .metainfo
            .begin_copy_object(src_bucket, src_key, src_enc, dst_bucket, dst_enc.clone())
            .await?;
        let cipher = encryption_from_params(begin.encryption_parameters.as_ref()).0;
        let (new_meta_key, new_meta_nonce) = reencrypt_metadata_key(
            &begin.encrypted_metadata_key,
            &begin.encrypted_metadata_key_nonce,
            cipher,
            &old_content,
            &new_content,
        )?;
        let new_segment_keys =
            reencrypt_segment_keys(&begin.segment_keys, cipher, &old_content, &new_content)?;
        let finished = self
            .inner
            .metainfo
            .finish_copy_object(
                dst_bucket,
                dst_key,
                FinishCopyObjectRequest {
                    stream_id: begin.stream_id,
                    new_bucket: dst_bucket.as_bytes().to_vec(),
                    new_encrypted_object_key: dst_enc,
                    new_encrypted_metadata_key_nonce: new_meta_nonce,
                    new_encrypted_metadata_key: new_meta_key,
                    new_segment_keys,
                    ..Default::default()
                },
            )
            .await?;
        let Some(pb) = finished.object else {
            return Err(Error::new(
                ErrorKind::Protocol,
                "FinishCopyObject returned no object",
            ));
        };
        object_from_info(
            pb,
            dst_bucket,
            dst_key,
            false,
            true,
            true,
            &self.inner.store,
        )
    }

    /// Move (server-side rename).
    pub async fn move_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> Result<()> {
        let (src_enc, dst_enc, old_content, new_content) =
            prepare_copy_move(self, src_bucket, src_key, dst_bucket, dst_key)?;
        let begin = self
            .inner
            .metainfo
            .begin_move_object(src_bucket, src_key, src_enc, dst_bucket, dst_enc.clone())
            .await?;
        let cipher = encryption_from_params(begin.encryption_parameters.as_ref()).0;
        let (new_meta_key, new_meta_nonce) = reencrypt_metadata_key(
            &begin.encrypted_metadata_key,
            &begin.encrypted_metadata_key_nonce,
            cipher,
            &old_content,
            &new_content,
        )?;
        let new_segment_keys =
            reencrypt_segment_keys(&begin.segment_keys, cipher, &old_content, &new_content)?;
        self.inner
            .metainfo
            .finish_move_object(
                src_bucket,
                src_key,
                FinishMoveObjectRequest {
                    stream_id: begin.stream_id,
                    new_bucket: dst_bucket.as_bytes().to_vec(),
                    new_encrypted_object_key: dst_enc,
                    new_encrypted_metadata_key_nonce: new_meta_nonce,
                    new_encrypted_metadata_key: new_meta_key,
                    new_segment_keys,
                    ..Default::default()
                },
            )
            .await
    }
}

struct ObjectListState {
    project: Project,
    bucket: String,
    prefix: String,
    parent_key: Key,
    path_cipher: CipherSuite,
    encrypted_prefix: Vec<u8>,
    encrypted_cursor: Vec<u8>,
    recursive: bool,
    system: bool,
    custom: bool,
    arbitrary_prefix: bool,
    pending: VecDeque<Object>,
    done: bool,
}

fn prepare_list(
    project: &Project,
    bucket: &str,
    opts: &ListObjectsOptions,
) -> Result<ObjectListState> {
    let parent_plain = opts
        .prefix
        .strip_suffix('/')
        .unwrap_or(opts.prefix.as_str());
    let encrypted_prefix =
        encrypt_path(bucket, parent_plain, &project.inner.store).map_err(map_enc)?;
    let parent_key =
        derive_path_key(bucket, parent_plain.as_bytes(), &project.inner.store).map_err(map_enc)?;
    let path_cipher = project
        .inner
        .store
        .lookup_unencrypted(bucket, parent_plain.as_bytes())
        .base
        .map(|b| {
            if b.path_cipher.0 == 0 {
                CipherSuite::AES_GCM
            } else {
                b.path_cipher
            }
        })
        .unwrap_or(CipherSuite::AES_GCM);
    let encrypted_cursor = if opts.cursor.is_empty() {
        Vec::new()
    } else {
        encrypt_iterator(
            PathIter::new(opts.cursor.as_bytes()),
            path_cipher,
            &parent_key,
        )
        .map_err(map_enc)?
    };
    Ok(ObjectListState {
        project: project.clone(),
        bucket: bucket.to_owned(),
        prefix: opts.prefix.clone(),
        parent_key,
        path_cipher,
        encrypted_prefix,
        encrypted_cursor,
        recursive: opts.recursive,
        system: opts.system,
        custom: opts.custom,
        arbitrary_prefix: path_cipher == CipherSuite::NULL,
        pending: VecDeque::new(),
        done: false,
    })
}

fn convert_list_page(st: &ObjectListState, items: Vec<ObjectListItem>) -> Result<Vec<Object>> {
    let mut out = Vec::new();
    for item in items {
        match convert_list_item(st, item) {
            Ok(obj) => out.push(obj),
            Err(e) if e.kind() == ErrorKind::DecryptionFailed => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

fn convert_list_item(st: &ObjectListState, item: ObjectListItem) -> Result<Object> {
    let rel = decrypt_iterator(
        PathIter::new(item.encrypted_object_key),
        st.path_cipher,
        &st.parent_key,
    )
    .map_err(map_enc)?;
    let rel = String::from_utf8(rel).map_err(|_| {
        Error::new(
            ErrorKind::DecryptionFailed,
            "listed object key is not utf-8",
        )
    })?;
    let key = if st.prefix.is_empty() {
        rel
    } else {
        format!("{}{rel}", st.prefix)
    };
    let is_prefix = item.status == ObjectStatus::Prefix as i32;
    let pb = storj_proto::metainfo::Object {
        bucket: st.bucket.as_bytes().to_vec(),
        encrypted_object_key: Vec::new(),
        status: item.status,
        created_at: item.created_at,
        expires_at: item.expires_at,
        encrypted_metadata_nonce: item.encrypted_metadata_nonce,
        encrypted_metadata: item.encrypted_metadata,
        encrypted_metadata_encrypted_key: item.encrypted_metadata_encrypted_key,
        encrypted_etag: item.encrypted_etag,
        plain_size: item.plain_size,
        stream_id: item.stream_id,
        ..Default::default()
    };
    object_from_info(
        pb,
        &st.bucket,
        &key,
        is_prefix,
        st.system,
        st.custom && !is_prefix,
        &st.project.inner.store,
    )
}

fn object_from_info(
    pb: storj_proto::metainfo::Object,
    bucket: &str,
    key: &str,
    is_prefix: bool,
    include_system: bool,
    include_custom: bool,
    store: &storj_encryption::Store,
) -> Result<Object> {
    let mut obj = object_from_proto(Some(pb.clone()), key);
    obj.is_prefix = is_prefix;
    if !include_system {
        obj.system = SystemMetadata::default();
    }
    if include_custom && !is_prefix && !pb.encrypted_metadata.is_empty() {
        obj.custom = decrypt_custom(&pb, bucket, key, store)?;
    } else {
        obj.custom = CustomMetadata::new();
    }
    Ok(obj)
}

fn decrypt_custom(
    pb: &storj_proto::metainfo::Object,
    bucket: &str,
    key: &str,
    store: &storj_encryption::Store,
) -> Result<CustomMetadata> {
    let content_key = derive_content_key(bucket, key.as_bytes(), store).map_err(map_enc)?;
    let (cipher, _) = encryption_from_params(pb.encryption_parameters.as_ref());
    let (_meta, custom) = decrypt_user_data(
        &pb.encrypted_metadata,
        &pb.encrypted_metadata_encrypted_key,
        &pb.encrypted_metadata_nonce,
        cipher,
        &content_key,
    )
    .map_err(map_uplink)?;
    Ok(custom.user_defined.into_iter().collect())
}

fn prepare_copy_move(
    project: &Project,
    src_bucket: &str,
    src_key: &str,
    dst_bucket: &str,
    dst_key: &str,
) -> Result<(Vec<u8>, Vec<u8>, Key, Key)> {
    require_bucket_name(src_bucket)?;
    require_object_key(src_key)?;
    require_bucket_name(dst_bucket)?;
    require_object_key(dst_key)?;
    let src_enc = encrypt_path(src_bucket, src_key, &project.inner.store).map_err(map_enc)?;
    let dst_enc = encrypt_path(dst_bucket, dst_key, &project.inner.store).map_err(map_enc)?;
    let old_content = derive_content_key(src_bucket, src_key.as_bytes(), &project.inner.store)
        .map_err(map_enc)?;
    let new_content = derive_content_key(dst_bucket, dst_key.as_bytes(), &project.inner.store)
        .map_err(map_enc)?;
    Ok((src_enc, dst_enc, old_content, new_content))
}

fn reencrypt_metadata_key(
    encrypted_key: &[u8],
    encrypted_nonce: &[u8],
    cipher: CipherSuite,
    old_content: &Key,
    new_content: &Key,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if encrypted_key.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let nonce = nonce_from_slice(encrypted_nonce).map_err(map_uplink)?;
    let meta_key = decrypt_key(encrypted_key, cipher, old_content, &nonce).map_err(map_uplink)?;
    let new_enc = encrypt_key(&meta_key, cipher, new_content, &nonce).map_err(map_uplink)?;
    Ok((new_enc, nonce.to_vec()))
}

fn reencrypt_segment_keys(
    keys: &[EncryptedKeyAndNonce],
    cipher: CipherSuite,
    old_content: &Key,
    new_content: &Key,
) -> Result<Vec<EncryptedKeyAndNonce>> {
    let mut out = Vec::with_capacity(keys.len());
    for old in keys {
        let nonce = nonce_from_slice(&old.encrypted_key_nonce).map_err(map_uplink)?;
        let content =
            decrypt_key(&old.encrypted_key, cipher, old_content, &nonce).map_err(map_uplink)?;
        let new_nonce = random_nonce();
        let new_enc = encrypt_key(&content, cipher, new_content, &new_nonce).map_err(map_uplink)?;
        out.push(EncryptedKeyAndNonce {
            position: old.position,
            encrypted_key_nonce: new_nonce.to_vec(),
            encrypted_key: new_enc,
        });
    }
    Ok(out)
}
