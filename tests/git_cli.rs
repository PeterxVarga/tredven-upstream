//! Bounded, disposable local Git repositories: no network, no real Tredven checkout.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static INDEX: AtomicUsize = AtomicUsize::new(0);

struct Repo {
    dir: PathBuf,
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("git installed");
    assert!(
        output.status.success(),
        "git {args:?} stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

impl Repo {
    fn seeded() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let index = INDEX.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "tredven-upstream-public-fixture-{}-{nonce}-{index}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        git(&dir, &["init", "--quiet"]);
        git(&dir, &["config", "user.name", "Test Contributor"]);
        git(&dir, &["config", "user.email", "test@example.test"]);
        fs::write(dir.join("README.md"), "baseline\n").unwrap();
        git(&dir, &["add", "README.md"]);
        git(&dir, &["commit", "-qm", "synthetic first"]);
        git(&dir, &["tag", "v1.0.0"]);
        fs::create_dir_all(dir.join("db/migrations")).unwrap();
        fs::create_dir_all(dir.join("src/api")).unwrap();
        fs::write(dir.join("db/migrations/002.sql"), "select 1;\n").unwrap();
        fs::write(dir.join("src/api/route.rs"), "pub fn route() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-qm", "synthetic upgrade"]);
        git(&dir, &["tag", "v1.1.0"]);
        Self { dir }
    }

    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tredven-upstream"))
            .args(args)
            .output()
            .unwrap()
    }

    fn run(&self, from: &str, to: &str) -> Output {
        self.cli(&[
            "inspect-git",
            "--repo",
            self.dir.to_str().unwrap(),
            "--project",
            "synthetic-example",
            "--from",
            from,
            "--to",
            to,
        ])
    }
}

#[test]
fn local_git_two_tag_diff_is_real_and_not_release_approval() {
    let repo = Repo::seeded();
    let before = git(&repo.dir, &["status", "--porcelain"]);
    let head = git(&repo.dir, &["rev-parse", "HEAD"]);
    let baseline = git(&repo.dir, &["rev-parse", "v1.0.0^{commit}"]);
    let candidate = git(&repo.dir, &["rev-parse", "v1.1.0^{commit}"]);
    let output = repo.run("v1.0.0", "v1.1.0");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["decision"], "REVIEW");
    assert_eq!(
        report["evidence_origin"],
        "LOCAL_GIT_OBJECTS_REMOTE_UNATTESTED"
    );
    assert_eq!(report["baseline_commit"], baseline);
    assert_eq!(report["candidate_commit"], candidate);
    assert_eq!(report["compare_coverage"], "complete");
    assert_eq!(report["changed_paths_considered"], 2);
    assert_eq!(report["impact_classes"]["MIGRATION_OR_SCHEMA"], 1);
    assert_eq!(report["impact_classes"]["API_OR_CONTRACT"], 1);
    assert_eq!(report["checks"][0]["status"], "not_run");
    assert_eq!(report["production_ready"], false);
    for flag in [
        "patch",
        "deploy",
        "send",
        "merge",
        "provider_writes",
        "paid_queries",
        "release",
    ] {
        assert_eq!(report["authority"][flag], false);
    }
    assert_eq!(git(&repo.dir, &["status", "--porcelain"]), before);
    assert_eq!(git(&repo.dir, &["rev-parse", "HEAD"]), head);
}

#[test]
fn same_tag_means_unknown_not_safe() {
    let repo = Repo::seeded();
    let out = repo.run("v1.0.0", "v1.0.0");
    assert_eq!(out.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["decision"], "UNKNOWN");
    assert_eq!(report["source_changed"], false);
    assert_eq!(report["authority"]["release"], false);
}

#[test]
fn missing_named_tag_fails_without_fallback_to_head() {
    let repo = Repo::seeded();
    let out = repo.run("v1.0.0", "v9.9.9");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("UNVERIFIED_REF")
    );
}

#[test]
fn git_ref_injection_is_rejected_before_git_launch() {
    let repo = Repo::seeded();
    let out = repo.run("v1.0.0", "--help");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("INVALID_LOCAL_GIT_TAG")
    );
}

#[test]
fn subdirectory_is_rejected_as_repository_root() {
    let repo = Repo::seeded();
    let out = repo.cli(&[
        "inspect-git",
        "--repo",
        repo.dir.join("db").to_str().unwrap(),
        "--project",
        "synthetic",
        "--from",
        "v1.0.0",
        "--to",
        "v1.1.0",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("ROOT_REQUIRED")
    );
}

#[test]
fn uncommitted_and_untracked_changes_do_not_pollute_pinned_diff() {
    let repo = Repo::seeded();
    fs::write(repo.dir.join("README.md"), "dirty\n").unwrap();
    fs::write(repo.dir.join("untracked.txt"), "do not read me\n").unwrap();
    let out = repo.run("v1.0.0", "v1.1.0");
    assert_eq!(out.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["changed_paths_considered"], 2);
}

#[test]
fn migration_profile_rejects_unpinned_synthetic_tag_commits() {
    let repo = Repo::seeded();
    git(&repo.dir, &["tag", "v0.1.27", "v1.0.0"]);
    git(&repo.dir, &["tag", "v0.1.31", "v1.1.0"]);
    let output = repo.cli(&[
        "inspect-contract",
        "--repo",
        repo.dir.to_str().unwrap(),
        "--project",
        "open-seo",
        "--profile",
        "open-seo-v0.1.31-stripe-projects-0049",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let msg = String::from_utf8(output.stderr).unwrap();
    assert!(msg.contains("PINNED_PROFILE_RELEASE_COMMIT_MISMATCH"));
}

#[test]
fn migration_profile_rejects_wrong_profile_before_reading_source() {
    let repo = Repo::seeded();
    let output = repo.cli(&[
        "inspect-contract",
        "--repo",
        repo.dir.to_str().unwrap(),
        "--project",
        "open-seo",
        "--profile",
        "invented-upgrade",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let msg = String::from_utf8(output.stderr).unwrap();
    assert!(msg.contains("UNSUPPORTED_PINNED_CONTRACT_PROFILE"));
}

#[test]
fn local_git_external_diff_driver_is_not_executed() {
    let repo = Repo::seeded();
    // A test configuration that would break the check if Git invoked it.
    git(
        &repo.dir,
        &["config", "diff.external", "/definitely/does-not-exist"],
    );
    let out = repo.run("v1.0.0", "v1.1.0");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn markdown_includes_both_actual_commit_ids_and_no_authority() {
    let repo = Repo::seeded();
    let output = repo.cli(&[
        "inspect-git",
        "--repo",
        repo.dir.to_str().unwrap(),
        "--project",
        "synthetic",
        "--from",
        "v1.0.0",
        "--to",
        "v1.1.0",
        "--format",
        "markdown",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let markdown = String::from_utf8(output.stdout).unwrap();
    assert!(markdown.contains("LOCAL_GIT_OBJECTS_REMOTE_UNATTESTED"));
    assert!(markdown.contains("No deployment, patch, merge"));
    assert!(markdown.contains("MIGRATION_OR_SCHEMA"));
}
