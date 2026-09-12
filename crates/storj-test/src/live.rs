//! Live-satellite test helpers: `.env` loading, grant lookup, bucket cleanup.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use storj::ListObjectsOptions;

/// Load a `.env` file into the process environment once.
///
/// Existing process variables win (so `STORJ_ACCESS=... cargo test` still
/// overrides the file). Search order: `STORJ_ENV_FILE`, then `.env` walking
/// up from the current directory, then walking up from this crate's
/// `CARGO_MANIFEST_DIR` (so a parent-directory `.env` is found).
pub fn load_dotenv() {
    static LOAD: Once = Once::new();
    LOAD.call_once(|| {
        if let Some(path) = dotenv_path()
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            apply_dotenv(&text);
        }
    });
}

/// Serialized grant for live satellite tests.
///
/// `STORJ_ACCESS`, then `STORJ_INTEROP_ACCESS`, then `STORJ_SIM_ACCESS`.
/// Loads `.env` first.
pub fn live_access() -> Option<String> {
    load_dotenv();
    env_nonempty("STORJ_ACCESS").or_else(crate::interop_access)
}

/// Optional shared bucket from `STORJ_BUCKET` (after `.env` load).
pub fn live_bucket() -> Option<String> {
    load_dotenv();
    env_nonempty("STORJ_BUCKET")
}

/// Where a live test should write, plus how to clean up afterwards.
///
/// When `STORJ_BUCKET` is set, objects go under a unique prefix in that
/// bucket and the bucket is left in place. Otherwise a unique bucket is
/// created and deleted after the run.
#[derive(Clone)]
pub struct LiveTarget {
    /// Serialized access grant.
    pub grant: String,
    /// Bucket to write into.
    pub bucket: String,
    /// Object-key prefix (empty when the test owns a unique bucket).
    pub prefix: String,
    delete_bucket: bool,
}

impl fmt::Debug for LiveTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveTarget")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("delete_bucket", &self.delete_bucket)
            .finish_non_exhaustive()
    }
}

impl LiveTarget {
    /// Build a target from the environment / `.env`.
    ///
    /// `name` is a short label used in the unique bucket or key prefix.
    pub fn from_env(name: &str) -> Self {
        let grant = live_access().expect(
            "set STORJ_ACCESS (or STORJ_INTEROP_ACCESS), or put it in a .env file — see .env.example",
        );
        let id = unique_id();
        match live_bucket() {
            Some(bucket) => Self {
                grant,
                bucket,
                prefix: format!("{name}-{id}/"),
                delete_bucket: false,
            },
            None => Self {
                grant,
                bucket: format!("{name}-{id}"),
                prefix: String::new(),
                delete_bucket: true,
            },
        }
    }

    /// Object key inside this target (`prefix` + `rest`).
    pub fn key(&self, rest: &str) -> String {
        format!("{}{rest}", self.prefix)
    }
}

/// Run `body`, then delete either the unique bucket or the prefix objects.
pub async fn with_live_cleanup<F>(project: &storj::Project, target: &LiveTarget, body: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if target.delete_bucket {
        crate::with_bucket_cleanup(project, &target.bucket, body).await;
        return;
    }

    let outcome = tokio::spawn(body).await;
    let cleanup = delete_prefixed_objects(project, &target.bucket, &target.prefix).await;
    match &cleanup {
        Ok(n) => eprintln!(
            "cleanup: deleted {n} objects under {}/{}",
            target.bucket, target.prefix
        ),
        Err(e) => eprintln!(
            "cleanup: could not delete prefix {}/{}: {e}",
            target.bucket, target.prefix
        ),
    }
    if let Err(e) = outcome {
        match e.try_into_panic() {
            Ok(payload) => std::panic::resume_unwind(payload),
            Err(e) => panic!("test body failed: {e}"),
        }
    }
    cleanup.expect("live test objects must be deleted after the run");
}

async fn delete_prefixed_objects(
    project: &storj::Project,
    bucket: &str,
    prefix: &str,
) -> Result<usize, String> {
    let mut stream = project.list_objects(
        bucket,
        ListObjectsOptions {
            prefix: prefix.to_string(),
            recursive: true,
            ..Default::default()
        },
    );
    let mut deleted = 0usize;
    let mut errors = Vec::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(obj) if !obj.is_prefix => {
                if let Err(e) = project.delete_object(bucket, &obj.key).await {
                    errors.push(format!("delete {}: {e}", obj.key));
                } else {
                    deleted += 1;
                }
            }
            Ok(_) => {}
            Err(e) => errors.push(format!("list: {e}")),
        }
    }
    if errors.is_empty() {
        Ok(deleted)
    } else {
        Err(errors.join("; "))
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

fn unique_id() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn dotenv_path() -> Option<PathBuf> {
    if let Some(explicit) = env_nonempty("STORJ_ENV_FILE") {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
    }
    let starts = [
        std::env::current_dir().ok(),
        Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
    ];
    for start in starts.into_iter().flatten() {
        if let Some(found) = walk_up_env(&start) {
            return Some(found);
        }
    }
    None
}

fn walk_up_env(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join(".env");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn apply_dotenv(text: &str) {
    for (key, value) in parse_dotenv(text) {
        if std::env::var_os(&key).is_some() {
            continue;
        }
        // SAFETY: test-only load, serialized by `Once`. Same tradeoff as
        // dotenv crates: concurrent `getenv` from other test threads is
        // possible, but this runs before live tests read the grant.
        unsafe { std::env::set_var(key, value) };
    }
}

/// Parse `KEY=VALUE` lines. Quotes are stripped; `export ` is optional.
fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        out.push((key.to_string(), unquote(value.trim())));
    }
    out
}

fn unquote(value: &str) -> String {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skips_comments_and_strips_quotes() {
        let parsed = parse_dotenv(
            "\u{feff}# heading\n\
             STORJ_ACCESS=abc\n\
             STORJ_BUCKET=\"storj-test\"\n\
             export FOO='bar'\n\
             EMPTY=\n\
             not-a-line\n\
             BAZ = qux \n",
        );
        assert_eq!(
            parsed,
            vec![
                ("STORJ_ACCESS".into(), "abc".into()),
                ("STORJ_BUCKET".into(), "storj-test".into()),
                ("FOO".into(), "bar".into()),
                ("EMPTY".into(), "".into()),
                ("BAZ".into(), "qux".into()),
            ]
        );
    }

    #[test]
    fn key_joins_prefix() {
        let t = LiveTarget {
            grant: "redacted".into(),
            bucket: "storj-test".into(),
            prefix: "live-1/".into(),
            delete_bucket: false,
        };
        assert_eq!(t.key("hello.txt"), "live-1/hello.txt");
    }
}
