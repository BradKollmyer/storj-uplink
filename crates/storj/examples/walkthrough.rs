//! Parse an access grant, ensure a bucket, upload a small object, download it.

use storj::{Access, Project};
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> storj::Result<()> {
    let access = Access::parse(&std::env::args().nth(1).expect("grant"))?;
    let project = Project::open(&access).await?;
    project.ensure_bucket("logs").await?;

    let mut upload = project
        .upload_object("logs", "hello.txt", Default::default())
        .await?;
    upload.write_all(b"hello storj").await?;
    let _obj = upload.commit().await?;

    let mut download = project
        .download_object("logs", "hello.txt", Default::default())
        .await?;
    let mut buf = Vec::new();
    tokio::io::copy(&mut download, &mut buf).await?;
    download.close().await?;
    project.close().await?;
    Ok(())
}
