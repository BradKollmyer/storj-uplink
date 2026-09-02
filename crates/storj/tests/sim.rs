//! `storj-sim` integration. Nightly CI, not every PR (design Testing Strategy).
//!
//! ```text
//! export STORJ_SIM=1
//! export STORJ_SIM_ACCESS="$(storj-sim network env GATEWAY_0_ACCESS)"
//! cargo test -p storj --test sim -- --ignored
//! ```

use storj::Access;

#[test]
fn sim_env_is_opt_in() {
    if !storj_test::sim_enabled() {
        return;
    }
    assert!(
        storj_test::sim_access().is_some(),
        "STORJ_SIM=1 requires STORJ_SIM_ACCESS"
    );
}

#[tokio::test]
#[ignore = "nightly: storj-sim"]
async fn sim_walkthrough_empty_and_inline() {
    let grant = storj_test::sim_access().expect("STORJ_SIM_ACCESS");
    let access = Access::parse(&grant).expect("parse sim grant");
    let project = storj::Project::open(&access).await.expect("open");
    project.close().await.ok();
}
