use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static INDEX: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    root: PathBuf,
    repo: PathBuf,
    artifact: PathBuf,
    hash: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn git(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let idx = INDEX.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "tredven-plan-r5-{}-{nonce}-{idx}",
            std::process::id()
        ));
        let repo = root.join("source");
        fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.name", "Synthetic Maintainer"]);
        git(&repo, &["config", "user.email", "synthetic@example.test"]);
        fs::write(repo.join("README.md"), "before\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-qm", "before"]);
        git(&repo, &["tag", "v1.0"]);
        fs::write(repo.join("README.md"), "after\n").unwrap();
        fs::create_dir_all(repo.join("db/migrations")).unwrap();
        fs::write(repo.join("db/migrations/0002.sql"), "select 1;\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-qm", "after"]);
        git(&repo, &["tag", "v1.1"]);
        let artifact = root.join("scanner-result.json");
        let bytes =
            b"{\"synthetic\":true,\"diagnostic\":\"no vulnerabilities asserted by fixture\"}\n";
        fs::write(&artifact, bytes).unwrap();
        let hash = format!("{:x}", Sha256::digest(bytes));
        Self {
            root,
            repo,
            artifact,
            hash,
        }
    }
    fn manifest(&self, status: &str, hash: &str, include_artifact: bool) -> PathBuf {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repo)
            .args(["rev-parse", "refs/tags/v1.1^{commit}"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let candidate = String::from_utf8(output.stdout).unwrap().trim().to_owned();
        let checks = vec![json!({
            "id":"security-scan","source_tool":"osv-scanner",
            "status":status, "candidate_commit":candidate,
            "artifact": if include_artifact {
                json!({"path":self.artifact.to_str().unwrap(),"sha256":hash})
            } else { Value::Null }
        })];
        let plan = json!({
            "schema":"tredven.upstream.watch-plan.v1",
            "targets":[
                {"id":"service-a","group":"backend","enabled":true,
                 "repo":self.repo.to_str().unwrap(),"from_tag":"v1.0","to_tag":"v1.1",
                 "required_evidence":checks
                },
                {"id":"not-monitored","group":"backend","enabled":false,
                 "repo":"/definitely-nonexistent","from_tag":"none","to_tag":"none"}
            ]
        });
        let path = self.root.join("watch-plan.json");
        fs::write(&path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
        path
    }
    fn cli(&self, manifest: &Path, markdown: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"));
        command.args(["inspect-plan", "--manifest"]).arg(manifest);
        if markdown {
            command.args(["--format", "markdown"]);
        }
        command.output().unwrap()
    }
}
#[test]
fn passing_immutable_tool_artifact_and_git_diff_remain_review_not_safe() {
    let f = Fixture::new();
    let plan = f.manifest("passed", &f.hash, true);
    let out = f.cli(&plan, false);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["total_watched"], 1);
    assert_eq!(r["total_skipped"], 1);
    assert_eq!(r["total_review"], 1);
    assert_eq!(r["targets"][0]["decision"], "REVIEW");
    assert_eq!(
        r["targets"][0]["evidence"][0]["artifact_integrity"],
        "MATCHED"
    );
    assert_eq!(
        r["targets"][0]["evidence"][0]["candidate_binding"],
        "MATCHED"
    );
    assert_eq!(
        r["targets"][0]["source_inspection"]["changed_paths_considered"],
        2
    );
    assert_eq!(r["targets"][1]["decision"], "SKIPPED");
    assert_eq!(r["groups"]["backend"]["review"], 1);
    assert_eq!(r["external_tool_execution_attested"], false);
    assert_eq!(r["publisher_attested"], false);
    assert_eq!(r["production_ready"], false);
    assert_eq!(r["action_authorized"], false);
    assert_eq!(r["performed_remote_queries"], false);
    assert_eq!(r["performed_mutations"], false);
}
#[test]
fn incomplete_scanner_evidence_is_unknown_exit_three() {
    let f = Fixture::new();
    let plan = f.manifest("not_run", &f.hash, false);
    let out = f.cli(&plan, false);
    assert_eq!(out.status.code(), Some(3));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["targets"][0]["decision"], "UNKNOWN");
    assert_eq!(
        r["targets"][0]["evidence"][0]["reason"],
        "REQUIRED_CHECK_NOT_RUN"
    );
}
#[test]
fn passed_without_receipt_is_unknown_not_green() {
    let f = Fixture::new();
    let plan = f.manifest("passed", &f.hash, false);
    let out = f.cli(&plan, false);
    assert_eq!(out.status.code(), Some(3));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["targets"][0]["decision"], "UNKNOWN");
}
#[test]
fn stale_scanner_artifact_with_wrong_release_pin_is_blocked() {
    let f = Fixture::new();
    let original = f.manifest("passed", &f.hash, true);
    let mut p: Value = serde_json::from_slice(&fs::read(original).unwrap()).unwrap();
    p["targets"][0]["required_evidence"][0]["candidate_commit"] = "a".repeat(40).into();
    let file = f.root.join("stale-plan.json");
    fs::write(&file, serde_json::to_vec(&p).unwrap()).unwrap();
    let out = f.cli(&file, false);
    assert_eq!(out.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["targets"][0]["decision"], "BLOCKED");
    assert_eq!(
        r["targets"][0]["evidence"][0]["reason"],
        "EVIDENCE_BOUND_TO_DIFFERENT_RELEASE"
    );
}
#[test]
fn unbound_scanner_pass_is_unknown_even_with_correct_hash() {
    let f = Fixture::new();
    let original = f.manifest("passed", &f.hash, true);
    let mut p: Value = serde_json::from_slice(&fs::read(original).unwrap()).unwrap();
    p["targets"][0]["required_evidence"][0]
        .as_object_mut()
        .unwrap()
        .remove("candidate_commit");
    let file = f.root.join("unbound-plan.json");
    fs::write(&file, serde_json::to_vec(&p).unwrap()).unwrap();
    let out = f.cli(&file, false);
    assert_eq!(out.status.code(), Some(3));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["targets"][0]["decision"], "UNKNOWN");
    assert_eq!(
        r["targets"][0]["evidence"][0]["reason"],
        "PASS_NOT_BOUND_TO_SOURCE_COMMIT"
    );
}
#[test]
fn tampered_artifact_hash_blocks_any_upgrade() {
    let f = Fixture::new();
    let plan = f.manifest("passed", &"0".repeat(64), true);
    let out = f.cli(&plan, false);
    assert_eq!(out.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["targets"][0]["decision"], "BLOCKED");
    assert_eq!(
        r["targets"][0]["evidence"][0]["reason"],
        "ARTIFACT_HASH_MISMATCH"
    );
}
#[test]
fn failed_required_ci_blocks_even_without_an_artifact() {
    let f = Fixture::new();
    let plan = f.manifest("failed", &f.hash, false);
    let out = f.cli(&plan, false);
    assert_eq!(out.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["targets"][0]["decision"], "BLOCKED");
}
#[test]
fn markdown_report_is_readable_without_side_effects() {
    let f = Fixture::new();
    let plan = f.manifest("passed", &f.hash, true);
    let out = f.cli(&plan, true);
    assert_eq!(out.status.code(), Some(0));
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("service-a / backend / Review"));
    assert!(s.contains("SKIPPED") || s.contains("Skipped"));
    assert!(s.contains("No release, deploy, merge, send"));
}
#[test]
fn symlink_manifest_is_rejected() {
    #[cfg(unix)]
    {
        let f = Fixture::new();
        let real = f.manifest("passed", &f.hash, true);
        let link = f.root.join("link.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let out = f.cli(&link, false);
        assert_eq!(out.status.code(), Some(1));
        assert!(
            String::from_utf8(out.stderr)
                .unwrap()
                .contains("REGULAR_FILE")
        );
    }
}
#[test]
fn symlink_artifact_cannot_count_as_verified_pass() {
    #[cfg(unix)]
    {
        let f = Fixture::new();
        let link = f.root.join("art-link.json");
        std::os::unix::fs::symlink(&f.artifact, &link).unwrap();
        let mut plan: Value =
            serde_json::from_slice(&fs::read(f.manifest("passed", &f.hash, true)).unwrap())
                .unwrap();
        plan["targets"][0]["required_evidence"][0]["artifact"]["path"] =
            link.to_str().unwrap().into();
        let file = f.root.join("linked-plan.json");
        fs::write(&file, serde_json::to_vec(&plan).unwrap()).unwrap();
        let out = f.cli(&file, false);
        assert_eq!(out.status.code(), Some(3));
        let r: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(r["targets"][0]["decision"], "UNKNOWN");
        assert_eq!(
            r["targets"][0]["evidence"][0]["artifact_integrity"],
            "UNSAFE_FILE"
        );
    }
}
