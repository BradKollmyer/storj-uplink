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
    pub(crate) next_segment: i32,
    pub(crate) total_plain: i64,
    pub(crate) last_segment_plain: i64,
    pub(crate) pending_flush: Option<tokio::task::JoinHandle<Result<FlushedSegment>>>,
    pub(crate) part_number: i32,
    pub(crate) etag: Option<Vec<u8>>,
    /// Set once a background segment flush fails. Every later write, flush,
    /// shutdown and commit returns this error so a caller that ignores one
    /// write error cannot publish an object with a missing segment.
    pub(crate) failed: Option<(ErrorKind, String)>,
}

pub(crate) struct FlushedSegment {
    pub(crate) index: i32,
    pub(crate) plain_size: i64,
}

impl UploadInner {
    /// The sticky flush error, if any.
    pub(crate) fn failed_error(&self) -> Option<Error> {
        self.failed
            .as_ref()
            .map(|(kind, msg)| Error::new(*kind, format!("upload failed earlier: {msg}")))
    }

    fn poison(&mut self, e: Error) -> Error {
        if self.failed.is_none() {
            self.failed = Some((e.kind(), e.to_string()));
        }
        e
    }

    pub(crate) fn apply_flush(&mut self, flushed: FlushedSegment) {
        self.next_segment = self.next_segment.max(flushed.index + 1);
        self.total_plain += flushed.plain_size;
        self.last_segment_plain = flushed.plain_size;
    }

    pub(crate) fn poll_pending_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if let Some(e) = self.failed_error() {
            return Poll::Ready(Err(e));
        }
        let Some(mut handle) = self.pending_flush.take() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(&mut handle).poll(cx) {
            Poll::Pending => {
                self.pending_flush = Some(handle);
                Poll::Pending
            }
            Poll::Ready(join) => {
                let flushed = match join {
                    Ok(Ok(f)) => f,
                    Ok(Err(e)) => return Poll::Ready(Err(self.poison(e))),
                    Err(e) => {
                        let e = Error::from(e);
                        return Poll::Ready(Err(self.poison(e)));
                    }
                };
                self.apply_flush(flushed);
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let max = crate::constants::MAX_SEGMENT_SIZE as usize;
        loop {
            match self.poll_pending_flush(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending if self.plaintext.len() >= max => return Poll::Pending,
                Poll::Pending | Poll::Ready(Ok(())) => {}
            }
            // A following write proves this full window is not last; hold it for ETag otherwise.
            if self.plaintext.len() >= max && self.pending_flush.is_none() {
                crate::project::spawn_flush_segment(self);
                continue;
            }
            let room = max.saturating_sub(self.plaintext.len());
            if room == 0 {
                return Poll::Pending;
            }
            let n = buf.len().min(room);
            self.plaintext.extend_from_slice(&buf[..n]);
            return Poll::Ready(Ok(n));
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.poll_pending_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
        }
    }
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
        let Some(mut inner) = self.lock_inner().take() else {
            return;
        };
        if let Some(handle) = inner.pending_flush.take() {
            handle.abort();
        }
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = crate::project::abort_upload(inner).await;
            });
        }
    }
}

impl AsyncWrite for Upload {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut g = self.lock_inner();
        let Some(inner) = g.as_mut() else {
            return Poll::Ready(Err(upload_done().into()));
        };
        inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut g = self.lock_inner();
        let Some(inner) = g.as_mut() else {
            return Poll::Ready(Err(upload_done().into()));
        };
        inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Does not CommitObject. Drop without commit still aborts.
        Poll::Ready(Ok(()))
    }
}

/// Object download. Implements `AsyncRead`. `info()` is populated at start.
///
/// Streams at **segment granularity**: segments are fetched, erasure-decoded
/// and decrypted one at a time by a background task that runs at most one
/// segment ahead of the reader, so memory is bounded by about two segments
/// (≈128 MiB worst case) however large the object is. Dropping or closing the
/// download cancels the background task and releases its storage-node
/// connections.
pub struct Download {
    info: Object,
    buf: Vec<u8>,
    pos: usize,
    rx: Option<tokio::sync::mpsc::Receiver<Result<Vec<u8>>>>,
    producer: Option<tokio::task::JoinHandle<()>>,
    /// Plaintext bytes still expected from the producer.
    remaining: i64,
}

impl Download {
    /// An already-materialized (empty or inline) body.
    pub(crate) fn new(info: Object, buf: Vec<u8>) -> Self {
        Self {
            info,
            buf,
            pos: 0,
            rx: None,
            producer: None,
            remaining: 0,
        }
    }

    pub(crate) fn streaming(
        info: Object,
        rx: tokio::sync::mpsc::Receiver<Result<Vec<u8>>>,
        producer: tokio::task::JoinHandle<()>,
        total: i64,
    ) -> Self {
        Self {
            info,
            buf: Vec::new(),
            pos: 0,
            rx: Some(rx),
            producer: Some(producer),
            remaining: total,
        }
    }

    /// Object info available immediately.
    pub fn info(&self) -> &Object {
        &self.info
    }

    /// Stop fetching: cancels the background segment task and releases its
    /// storage-node connections. Drop does the same (best-effort).
    pub async fn close(mut self) -> Result<()> {
        self.cancel();
        Ok(())
    }

    fn cancel(&mut self) {
        if let Some(task) = self.producer.take() {
            task.abort();
        }
        self.rx = None;
    }
}

impl Drop for Download {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl AsyncRead for Download {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pos < this.buf.len() {
                let n = buf.remaining().min(this.buf.len() - this.pos);
                buf.put_slice(&this.buf[this.pos..this.pos + n]);
                this.pos += n;
                return Poll::Ready(Ok(()));
            }
            let Some(rx) = this.rx.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            match rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(segment))) => {
                    this.remaining -= i64::try_from(segment.len()).unwrap_or(i64::MAX);
                    this.buf = segment;
                    this.pos = 0;
                }
                Poll::Ready(Some(Err(e))) => {
                    this.cancel();
                    return Poll::Ready(Err(e.into()));
                }
                Poll::Ready(None) => {
                    this.cancel();
                    if this.remaining != 0 {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::Protocol,
                            "download missing segment data",
                        )
                        .into()));
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

/// Part of a multipart upload. Implements `AsyncWrite`.
pub struct PartUpload {
    info: Part,
    inner: Mutex<Option<UploadInner>>,
}

impl PartUpload {
    pub(crate) fn new(info: Part, inner: UploadInner) -> Self {
        Self {
            info,
            inner: Mutex::new(Some(inner)),
        }
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, Option<UploadInner>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Set ETag for this part. Must be called before [`commit`](Self::commit).
    pub async fn set_etag(&mut self, etag: &[u8]) -> Result<()> {
        {
            let mut g = self.lock_inner();
            let inner = g.as_mut().ok_or_else(upload_done)?;
            if inner.etag.is_some() {
                return Err(Error::new(ErrorKind::Protocol, "etag already set"));
            }
            inner.etag = Some(etag.to_vec());
        }
        self.info.etag = etag.to_vec();
        Ok(())
    }

    /// Commit this part. Does not publish the object; call `Project::commit_upload`.
    pub async fn commit(self) -> Result<()> {
        let inner = self.lock_inner().take().ok_or_else(upload_done)?;
        crate::project::commit_part(inner).await
    }

    /// Abort this part. Already committed segments of the part are left in place.
    pub async fn abort(self) -> Result<()> {
        let inner = self.lock_inner().take().ok_or_else(upload_done)?;
        crate::project::abort_part(inner).await
    }

    /// Last information about the part.
    pub fn info(&self) -> &Part {
        &self.info
    }
}

impl Drop for PartUpload {
    fn drop(&mut self) {
        let Some(mut inner) = self.lock_inner().take() else {
            return;
        };
        if let Some(handle) = inner.pending_flush.take() {
            handle.abort();
        }
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = crate::project::abort_part(inner).await;
            });
        }
    }
}

impl AsyncWrite for PartUpload {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut g = self.lock_inner();
        let Some(inner) = g.as_mut() else {
            return Poll::Ready(Err(upload_done().into()));
        };
        inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut g = self.lock_inner();
        let Some(inner) = g.as_mut() else {
            return Poll::Ready(Err(upload_done().into()));
        };
        inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn upload_done() -> Error {
    Error::new(
        ErrorKind::UploadDone,
        "upload done: already committed or aborted",
    )
}
