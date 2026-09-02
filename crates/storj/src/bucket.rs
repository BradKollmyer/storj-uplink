//! Bucket metadata conversion and `Project` bucket CRUD.

use std::collections::VecDeque;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::stream;

use storj_proto::metainfo::{Bucket as ProtoBucket, BucketListItem};

use crate::error::{Error, ErrorKind, Result};
use crate::project::{BucketStream, Project};
use crate::types::{Bucket, ListBucketsOptions};

/// Empty name is invalid (Go `metaclient.ErrNoBucket`).
pub(crate) fn require_bucket_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::new(
            ErrorKind::BucketNameInvalid,
            r#"bucket name invalid ("")"#,
        ));
    }
    Ok(())
}

pub(crate) fn proto_timestamp(ts: Option<prost_types::Timestamp>) -> SystemTime {
    match ts {
        Some(t) if t.seconds >= 0 && t.nanos >= 0 => {
            UNIX_EPOCH + Duration::new(t.seconds as u64, t.nanos as u32)
        }
        _ => UNIX_EPOCH,
    }
}

pub(crate) fn bucket_from_proto(pb: Option<ProtoBucket>, fallback_name: &str) -> Result<Bucket> {
    let Some(pb) = pb else {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("satellite returned no bucket ({fallback_name:?})"),
        ));
    };
    let name = if pb.name.is_empty() {
        fallback_name.to_owned()
    } else {
        String::from_utf8(pb.name).map_err(|e| {
            Error::new(
                ErrorKind::Protocol,
                format!("bucket name is not utf-8: {e}"),
            )
        })?
    };
    Ok(Bucket {
        name,
        created: proto_timestamp(pb.created_at),
    })
}

pub(crate) fn bucket_from_list_item(item: BucketListItem) -> Result<Bucket> {
    let name = String::from_utf8(item.name).map_err(|e| {
        Error::new(
            ErrorKind::Protocol,
            format!("bucket name is not utf-8: {e}"),
        )
    })?;
    Ok(Bucket {
        name,
        created: proto_timestamp(item.created_at),
    })
}

impl Project {
    /// Create a bucket. Already-exists → `BucketAlreadyExists` with `Error::bucket()`.
    pub async fn create_bucket(&self, name: &str) -> Result<Bucket> {
        require_bucket_name(name)?;
        match self.inner.metainfo.create_bucket(name).await {
            Ok(bucket) => Ok(bucket),
            Err(e) if e.kind() == ErrorKind::BucketAlreadyExists => {
                match self.inner.metainfo.get_bucket(name).await {
                    Ok(existing) => Err(e.with_bucket(existing)),
                    // Do not invent a UNIX_EPOCH placeholder; ensure_bucket
                    // must not treat a failed Stat as success.
                    Err(stat_err) => Err(e.with_source(stat_err)),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Create the bucket if missing; return it either way.
    ///
    /// If create reports already-exists but could not stat the existing bucket,
    /// this fails rather than returning a placeholder.
    pub async fn ensure_bucket(&self, name: &str) -> Result<Bucket> {
        match self.create_bucket(name).await {
            Ok(bucket) => Ok(bucket),
            Err(e) if e.kind() == ErrorKind::BucketAlreadyExists => {
                if let Some(bucket) = e.bucket() {
                    return Ok(bucket.clone());
                }
                self.stat_bucket(name).await
            }
            Err(e) => Err(e),
        }
    }

    /// Bucket metadata.
    pub async fn stat_bucket(&self, name: &str) -> Result<Bucket> {
        require_bucket_name(name)?;
        self.inner.metainfo.get_bucket(name).await
    }

    /// Delete an empty bucket.
    pub async fn delete_bucket(&self, name: &str) -> Result<Bucket> {
        require_bucket_name(name)?;
        self.inner.metainfo.delete_bucket(name, false).await
    }

    /// Delete a bucket and all of its objects.
    pub async fn delete_bucket_with_objects(&self, name: &str) -> Result<Bucket> {
        require_bucket_name(name)?;
        self.inner.metainfo.delete_bucket(name, true).await
    }

    /// List buckets. First returned name is after `opts.cursor`.
    pub fn list_buckets(&self, opts: ListBucketsOptions) -> BucketStream {
        let project = self.clone();
        Box::pin(stream::try_unfold(
            ListState {
                project,
                cursor: opts.cursor.unwrap_or_default(),
                pending: VecDeque::new(),
                done: false,
            },
            |mut st| async move {
                loop {
                    if let Some(bucket) = st.pending.pop_front() {
                        return Ok(Some((bucket, st)));
                    }
                    if st.done {
                        return Ok(None);
                    }
                    let (items, more) = st
                        .project
                        .inner
                        .metainfo
                        .list_buckets_page(&st.cursor, 0)
                        .await?;
                    if items.is_empty() {
                        st.done = true;
                        continue;
                    }
                    st.cursor = items.last().map(|b| b.name.clone()).unwrap_or_default();
                    st.done = !more;
                    st.pending.extend(items);
                }
            },
        ))
    }
}

struct ListState {
    project: Project,
    cursor: String,
    pending: VecDeque<Bucket>,
    done: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_name_is_invalid() {
        let e = require_bucket_name("").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::BucketNameInvalid);
    }

    #[test]
    fn non_empty_name_ok() {
        require_bucket_name("logs").unwrap();
    }
}
