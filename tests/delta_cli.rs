//! End-to-end CLI coverage of R7 baseline-vs-candidate scanner comparisons.
//! Only disposable synthetic local Git repositories; no scanner process,
//! network, server, deploy, email or credential.
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    dir: PathBuf,
    source: PathBuf,
    base_sha: String,
    candidate_sha: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
impl Fixture {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "tredven-delta-r7-{}-{now}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::SeqCst)
        ));
        let source = dir.join("source");
        fs::create_dir_all(&source).unwrap();
        git(&source, &["init", "-q"]);
        git(&source, &["config", "user.name", "Synthetic Tester"]);
        git(&source, &["config", "user.email", "fixture@example.test"]);
        fs::write(source.join("CHANGELOG.md"), "before\n").unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "-qm", "base"]);
        git(&source, &["tag", "v1.0"]);
        let base_sha = git(&source, &["rev-parse", "HEAD"]);
        fs::write(source.join("CHANGELOG.md"), "after\n").unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "-qm", "candidate"]);
        git(&source, &["tag", "v1.1"]);
        let candidate_sha = git(&source, &["rev-parse", "HEAD"]);
        Self {
            dir,
            source,
            base_sha,
            candidate_sha,
        }
    }
    fn copy(&self, name: &str, local: &str) -> PathBuf {
        let target = self.dir.join(local);
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/scanner")
                .join(name),
            &target,
        )
        .unwrap();
        target
    }
    fn scan_delta(&self, base: &Path, after: &Path, format: &str, subject: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tredven-upstream"))
            .args(["inspect-delta", "--baseline"])
            .arg(base)
            .args(["--candidate"])
            .arg(after)
            .args(["--scanner", format, "--subject", subject])
            .output()
            .unwrap()
    }
    fn upgrade_delta(
        &self,
        base: &Path,
        after: &Path,
        format: &str,
        subject: &str,
        base_sha: &str,
        candidate_sha: &str,
    ) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tredven-upstream"))
            .args(["inspect-upgrade-delta", "--repo"])
            .arg(&self.source)
            .args([
                "--project",
                "synthetic",
                "--from",
                "v1.0",
                "--to",
                "v1.1",
                "--baseline",
            ])
            .arg(base)
            .args(["--candidate"])
            .arg(after)
            .args([
                "--scanner",
                format,
                "--subject",
                subject,
                "--baseline-commit",
                base_sha,
                "--candidate-commit",
                candidate_sha,
            ])
            .output()
            .unwrap()
    }
}
const TRIVY: &str = "example/app@sha256:synthetic-candidate";
#[test]
fn two_real_shaped_json_files_report_new_critical_then_absolute_block() {
    let x = Fixture::new();
    let a = x.copy("trivy-clean.json", "before.json");
    let b = x.copy("trivy-critical.json", "after.json");
    let out = x.scan_delta(&a, &b, "trivy-json-v2", TRIVY);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["new_occurrences"], 1);
    assert_eq!(r["new_blocking_occurrences"], 1);
    assert_eq!(r["resolved_occurrences"], 0);
    assert_eq!(r["delta_decision"], "BLOCKED");
    assert_eq!(r["overall_decision"], "BLOCKED");
    assert_eq!(r["new_sample"][0]["id"], "SYNTHETIC-TEST-0001");
    assert_eq!(r["scanner_execution_attested"], false);
    assert_eq!(r["production_ready"], false);
}
#[test]
fn persistent_critical_has_no_new_finding_but_is_still_blocked() {
    let x = Fixture::new();
    let a = x.copy("trivy-critical.json", "before.json");
    let b = x.copy("trivy-critical.json", "after.json");
    let out = x.scan_delta(&a, &b, "trivy-json-v2", TRIVY);
    assert_eq!(out.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["new_occurrences"], 0);
    assert_eq!(r["persistent_occurrences"], 1);
    assert_eq!(r["delta_decision"], "REVIEW");
    assert_eq!(r["overall_decision"], "BLOCKED");
    assert_eq!(r["identical_report_bytes"], true);
    assert_eq!(r["action_authorized"], false);
}
#[test]
fn critical_disappeared_is_diagnostic_review_not_release_approval() {
    let x = Fixture::new();
    let a = x.copy("trivy-critical.json", "before.json");
    let b = x.copy("trivy-clean.json", "after.json");
    let out = x.scan_delta(&a, &b, "trivy-json-v2", TRIVY);
    assert_eq!(out.status.code(), Some(0));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["resolved_occurrences"], 1);
    assert_eq!(r["overall_decision"], "REVIEW");
    assert_eq!(r["production_ready"], false);
    assert_eq!(r["remote_publisher_attested"], false);
}
#[test]
fn unknown_baseline_does_not_claim_zero_new_findings() {
    let x = Fixture::new();
    let a = x.copy("trivy-empty.json", "before.json");
    let b = x.copy("trivy-clean.json", "after.json");
    let out = x.scan_delta(&a, &b, "trivy-json-v2", TRIVY);
    assert_eq!(out.status.code(), Some(3));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(r["new_occurrences"].is_null());
    assert_eq!(r["comparable_scan_scope"], false);
}
#[test]
fn osv_new_vulnerability_blocked_in_existing_package() {
    let x = Fixture::new();
    let a = x.copy("osv-clean.json", "before.json");
    let b = x.copy("osv-vulnerable.json", "after.json");
    let out = x.scan_delta(&a, &b, "osv-scanner-json-v2", "Cargo.lock");
    assert_eq!(out.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["new_occurrences"], 1);
    assert_eq!(r["new_blocking_occurrences"], 1);
    assert_eq!(r["overall_decision"], "BLOCKED");
}
#[test]
fn one_command_local_git_tags_plus_two_native_reports_block_new_high() {
    let x = Fixture::new();
    let a = x.copy("trivy-clean.json", "before.json");
    let b = x.copy("trivy-critical.json", "after.json");
    let out = x.upgrade_delta(
        &a,
        &b,
        "trivy-json-v2",
        TRIVY,
        &x.base_sha,
        &x.candidate_sha,
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["source"]["changed_paths_considered"], 1);
    assert_eq!(r["baseline_commit_binding"], true);
    assert_eq!(r["candidate_commit_binding"], true);
    assert_eq!(r["decision"], "BLOCKED");
    assert_eq!(r["scanner_delta"]["new_occurrences"], 1);
    assert_eq!(r["production_ready"], false);
    assert_eq!(r["action_authorized"], false);
}
#[test]
fn one_command_false_candidate_pin_blocks_even_when_no_new_findings() {
    let x = Fixture::new();
    let a = x.copy("trivy-clean.json", "before.json");
    let b = x.copy("trivy-clean.json", "after.json");
    let out = x.upgrade_delta(&a, &b, "trivy-json-v2", TRIVY, &x.base_sha, &"0".repeat(40));
    assert_eq!(out.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["candidate_commit_binding"], false);
    assert_eq!(r["decision"], "BLOCKED");
    assert_eq!(r["reason"], "SCANNER_SOURCE_COMMIT_DECLARATION_MISMATCH");
}
#[test]
fn one_command_false_baseline_pin_blocks() {
    let x = Fixture::new();
    let a = x.copy("osv-clean.json", "before.json");
    let b = x.copy("osv-clean.json", "after.json");
    let out = x.upgrade_delta(
        &a,
        &b,
        "osv-scanner-json-v2",
        "Cargo.lock",
        &"a".repeat(40),
        &x.candidate_sha,
    );
    assert_eq!(out.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["baseline_commit_binding"], false);
    assert_eq!(r["decision"], "BLOCKED");
}
#[test]
fn standalone_fails_closed_for_symlinked_scan_file() {
    #[cfg(unix)]
    {
        let x = Fixture::new();
        let a = x.copy("trivy-clean.json", "before.json");
        let b = x.dir.join("link.json");
        std::os::unix::fs::symlink(&a, &b).unwrap();
        let out = x.scan_delta(&a, &b, "trivy-json-v2", TRIVY);
        assert_eq!(out.status.code(), Some(1));
        assert!(
            String::from_utf8(out.stderr)
                .unwrap()
                .contains("BOUNDED_REGULAR_FILE")
        );
    }
}
#[test]
fn malformed_or_cross_scope_comparison_reports_unknown_not_zero() {
    let x = Fixture::new();
    let a = x.copy("trivy-clean.json", "before.json");
    let b = x.dir.join("wrong-scope.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&a).unwrap()).unwrap();
    value["Results"][0]["Target"] = json!("different-target");
    fs::write(&b, serde_json::to_vec(&value).unwrap()).unwrap();
    let out = x.scan_delta(&a, &b, "trivy-json-v2", TRIVY);
    assert_eq!(out.status.code(), Some(3));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(r["new_occurrences"].is_null());
    assert_eq!(r["reason"], "SCANNER_TARGET_SETS_DIFFER_CANNOT_COMPARE");
}
