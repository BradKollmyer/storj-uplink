//! `Project` — bucket and object operations.

use std::pin::Pin;
use std::sync::Arc;

use futures_core::Stream;
use futures_util::stream;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::access::Access;
use crate::error::{Error, Result};
use crate::metainfo::{MetainfoClient, parse_satellite_url};
use crate::types::{
    Bucket, BucketObjectLockConfiguration, CommitUploadOptions, Config, CustomMetadata,
    DownloadOptions, ListObjectsOptions, ListUploadPartsOptions, ListUploadsOptions, Object,
    Retention, SetObjectRetentionOptions, UploadInfo, UploadOptions,
};
use crate::upload::{Download, PartUpload, Upload};

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
        Ok(Self {
            inner: Arc::new(ProjectInner { metainfo }),
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
        let _ = (bucket, key, opts);
        Err(Error::not_implemented("Project::upload_object"))
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
