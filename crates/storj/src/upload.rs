//! Upload / download / part-upload handles. I/O pipeline lands in later PRs.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, Result};
use crate::types::{CustomMetadata, Object, Part};

/// In-progress object upload. Implements `AsyncWrite`. Must `commit()` to publish.
pub struct Upload {
    info: Object,
}

impl Upload {
    #[allow(dead_code)]
    pub(crate) fn stub(info: Object) -> Self {
        Self { info }
    }

    /// Custom metadata applied at commit.
    pub async fn set_custom_metadata(&mut self, meta: CustomMetadata) -> Result<()> {
        let _ = meta;
        Err(Error::not_implemented("Upload::set_custom_metadata"))
    }

    /// Flush remaining stripes, shut down piece RPCs, then `CommitObject`.
    /// `poll_shutdown` does **not** commit.
    pub async fn commit(self) -> Result<Object> {
        Err(Error::not_implemented("Upload::commit"))
    }

    /// Abort an uncommitted upload.
    pub async fn abort(self) -> Result<()> {
        Err(Error::not_implemented("Upload::abort"))
    }

    /// Object info populated at `upload_object` return.
    pub fn info(&self) -> &Object {
        &self.info
    }
}

impl AsyncWrite for Upload {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Err(Error::not_implemented("Upload::poll_write").into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Object download. Implements `AsyncRead`.
pub struct Download {
    info: Object,
}

impl Download {
    #[allow(dead_code)]
    pub(crate) fn stub(info: Object) -> Self {
        Self { info }
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
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(Error::not_implemented("Download::poll_read").into()))
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
