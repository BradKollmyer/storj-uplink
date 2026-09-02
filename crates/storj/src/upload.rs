//! Upload / download / part-upload handles.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, ErrorKind, Result};
use crate::project::ProjectInner;
use crate::types::{CustomMetadata, Object, Part};

/// In-progress object upload. Implements `AsyncWrite`. Must `commit()` to publish.
pub struct Upload {
    info: Object,
    inner: Mutex<Option<UploadInner>>,
}

pub(crate) struct UploadInner {
    pub(crate) project: Arc<ProjectInner>,
    pub(crate) bucket: String,
    pub(crate) key: String,
    pub(crate) encrypted_object_key: Vec<u8>,
    pub(crate) stream_id: Vec<u8>,
    pub(crate) content_key: storj_encryption::Key,
    pub(crate) cipher: storj_encryption::CipherSuite,
    pub(crate) block_size: usize,
    pub(crate) custom: CustomMetadata,
    pub(crate) plaintext: Vec<u8>,
}

impl Upload {
    pub(crate) fn new(info: Object, inner: UploadInner) -> Self {
        Self {
            info,
            inner: Mutex::new(Some(inner)),
        }
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, Option<UploadInner>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Custom metadata applied at commit.
    pub async fn set_custom_metadata(&mut self, meta: CustomMetadata) -> Result<()> {
        let mut g = self.lock_inner();
        let inner = g.as_mut().ok_or_else(|| {
            Error::new(
                ErrorKind::UploadDone,
                "upload done: already committed or aborted",
            )
        })?;
        inner.custom = meta;
        Ok(())
    }

    /// Flush remaining stripes, shut down piece RPCs, then `CommitObject`.
    /// `poll_shutdown` does **not** commit.
    pub async fn commit(self) -> Result<Object> {
        let inner = self.lock_inner().take().ok_or_else(|| {
            Error::new(
                ErrorKind::UploadDone,
                "upload done: already committed or aborted",
            )
        })?;
        crate::project::commit_upload(inner).await
    }

    /// Abort an uncommitted upload.
    pub async fn abort(self) -> Result<()> {
        let inner = self.lock_inner().take().ok_or_else(|| {
            Error::new(
                ErrorKind::UploadDone,
                "upload done: already committed or aborted",
            )
        })?;
        crate::project::abort_upload(inner).await
    }

    /// Object info populated at `upload_object` return.
    pub fn info(&self) -> &Object {
        &self.info
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        let Some(inner) = self.lock_inner().take() else {
            return;
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = crate::project::abort_upload(inner).await;
            });
        }
    }
}

impl AsyncWrite for Upload {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut g = self.lock_inner();
        let Some(inner) = g.as_mut() else {
            return Poll::Ready(Err(Error::new(
                ErrorKind::UploadDone,
                "upload done: already committed or aborted",
            )
            .into()));
        };
        let max = crate::constants::MAX_SEGMENT_SIZE as usize;
        if inner.plaintext.len() >= max {
            return Poll::Ready(Err(Error::new(
                ErrorKind::Protocol,
                "single-segment upload exceeds 64MiB",
            )
            .into()));
        }
        let room = max - inner.plaintext.len();
        let n = buf.len().min(room);
        inner.plaintext.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.lock_inner().is_none() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::UploadDone,
                "upload done: already committed or aborted",
            )
            .into()));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Does not CommitObject. Drop without commit still aborts.
        Poll::Ready(Ok(()))
    }
}

/// Object download. Implements `AsyncRead`. `info()` is populated at start.
pub struct Download {
    info: Object,
    buf: Vec<u8>,
    pos: usize,
}

impl Download {
    pub(crate) fn new(info: Object, buf: Vec<u8>) -> Self {
        Self { info, buf, pos: 0 }
    }

    /// Object info available immediately.
    pub fn info(&self) -> &Object {
        &self.info
    }

    /// Close piece RPCs. Drop is best-effort.
    pub async fn close(self) -> Result<()> {
        Ok(())
    }
}

impl AsyncRead for Download {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos >= this.buf.len() {
            return Poll::Ready(Ok(()));
        }
        let n = buf.remaining().min(this.buf.len() - this.pos);
        buf.put_slice(&this.buf[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

/// Part of a multipart upload. Implements `AsyncWrite`.
pub struct PartUpload {
    info: Part,
}

impl PartUpload {
    #[allow(dead_code)]
    pub(crate) fn stub(info: Part) -> Self {
        Self { info }
    }

    /// Set ETag for this part.
    pub async fn set_etag(&mut self, etag: &[u8]) -> Result<()> {
        let _ = etag;
        Err(Error::not_implemented("PartUpload::set_etag"))
    }

    /// Commit this part.
    pub async fn commit(self) -> Result<()> {
        Err(Error::not_implemented("PartUpload::commit"))
    }

    /// Abort this part.
    pub async fn abort(self) -> Result<()> {
        Err(Error::not_implemented("PartUpload::abort"))
    }

    /// Last information about the part.
    pub fn info(&self) -> &Part {
        &self.info
    }
}

impl AsyncWrite for PartUpload {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Err(Error::not_implemented("PartUpload::poll_write").into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
