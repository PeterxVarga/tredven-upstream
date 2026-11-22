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
impl Fixture {
    fn native_report(&self, filename: &str, scanner: &str, subject: &str) -> PathBuf {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/scanner")
            .join(filename);
        let bytes = fs::read(source).unwrap();
        fs::write(&self.artifact, &bytes).unwrap();
        let hash = format!("{:x}", Sha256::digest(&bytes));
        let old = self.manifest("unknown", &hash, true);
        let mut plan: Value = serde_json::from_slice(&fs::read(old).unwrap()).unwrap();
        let entry = &mut plan["targets"][0]["required_evidence"][0];
        entry["source_tool"] = if scanner.starts_with("trivy") {
            "trivy"
        } else {
            "osv-scanner"
        }
        .into();
        entry["scan"] = json!({"format":scanner,"expected_subject":subject});
        let path = self.root.join("native-plan.json");
        fs::write(&path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
        path
    }
}
fn native_case(
    filename: &str,
    scanner: &str,
    subject: &str,
    expected_code: i32,
    decision: &str,
    reason: &str,
) {
    let f = Fixture::new();
    let p = f.native_report(filename, scanner, subject);
    let out = f.cli(&p, false);
    assert_eq!(
        out.status.code(),
        Some(expected_code),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["targets"][0]["decision"], decision);
    assert_eq!(r["targets"][0]["evidence"][0]["reason"], reason);
    assert_eq!(
        r["targets"][0]["evidence"][0]["artifact_integrity"],
        "MATCHED"
    );
    assert_eq!(
        r["targets"][0]["evidence"][0]["candidate_binding"],
        "MATCHED"
    );
    assert_eq!(
        r["targets"][0]["evidence"][0]["origin"],
        "PARSED_SCANNER_JSON_TOOL_EXECUTION_NOT_ATTESTED"
    );
    assert_eq!(
        r["targets"][0]["evidence"][0]["scanner_summary"]["decision"],
        decision
    );
    assert_eq!(r["action_authorized"], false);
    assert_eq!(r["production_ready"], false);
    assert_eq!(r["performed_remote_queries"], false);
}
#[test]
fn trivy_critical_real_json_shape_blocks() {
    native_case(
        "trivy-critical.json",
        "trivy-json-v2",
        "example/app@sha256:synthetic-candidate",
        2,
        "BLOCKED",
        "NATIVE_SCANNER_BLOCKING_FINDING",
    );
}
#[test]
fn trivy_no_findings_still_requires_review_not_ready() {
    native_case(
        "trivy-clean.json",
        "trivy-json-v2",
        "example/app@sha256:synthetic-candidate",
        0,
        "REVIEW",
        "NATIVE_SCANNER_PARSED_REVIEW_ONLY",
    );
}
#[test]
fn trivy_empty_results_is_unknown_no_false_green() {
    native_case(
        "trivy-empty.json",
        "trivy-json-v2",
        "example/app@sha256:synthetic-candidate",
        3,
        "UNKNOWN",
        "NATIVE_SCANNER_COVERAGE_UNKNOWN",
    );
}
#[test]
fn trivy_secret_finding_blocks_without_exposing_secret_content() {
    native_case(
        "trivy-secret.json",
        "trivy-json-v2",
        "example/app@sha256:synthetic-candidate",
        2,
        "BLOCKED",
        "NATIVE_SCANNER_BLOCKING_FINDING",
    );
}
#[test]
fn trivy_mismatched_subject_blocks_even_if_clean() {
    native_case(
        "trivy-clean.json",
        "trivy-json-v2",
        "other/image",
        2,
        "BLOCKED",
        "NATIVE_SCANNER_BLOCKING_FINDING",
    );
}
#[test]
fn osv_advisory_blocks_without_cvss_guessing() {
    native_case(
        "osv-vulnerable.json",
        "osv-scanner-json-v2",
        "Cargo.lock",
        2,
        "BLOCKED",
        "NATIVE_SCANNER_BLOCKING_FINDING",
    );
}
#[test]
fn osv_scanned_clean_package_stays_review_not_safe() {
    native_case(
        "osv-clean.json",
        "osv-scanner-json-v2",
        "Cargo.lock",
        0,
        "REVIEW",
        "NATIVE_SCANNER_PARSED_REVIEW_ONLY",
    );
}
#[test]
fn osv_no_scanned_packages_does_not_become_pass() {
    native_case(
        "osv-empty.json",
        "osv-scanner-json-v2",
        "Cargo.lock",
        3,
        "UNKNOWN",
        "NATIVE_SCANNER_COVERAGE_UNKNOWN",
    );
}
#[test]
fn scanner_manual_pass_cannot_override_native_findings() {
    let f = Fixture::new();
    let path = f.native_report(
        "trivy-critical.json",
        "trivy-json-v2",
        "example/app@sha256:synthetic-candidate",
    );
    let mut plan: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    plan["targets"][0]["required_evidence"][0]["status"] = "passed".into();
    fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
    let output = f.cli(&path, false);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("INVALID_NATIVE_SCANNER_INPUT_CONTRACT")
    );
}
#[test]
fn scanner_stale_commit_is_rejected_before_parsing_report() {
    let f = Fixture::new();
    let path = f.native_report(
        "trivy-clean.json",
        "trivy-json-v2",
        "example/app@sha256:synthetic-candidate",
    );
    let mut plan: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    plan["targets"][0]["required_evidence"][0]["candidate_commit"] = "a".repeat(40).into();
    fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
    let output = f.cli(&path, false);
    assert_eq!(output.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        r["targets"][0]["evidence"][0]["reason"],
        "EVIDENCE_BOUND_TO_DIFFERENT_RELEASE"
    );
    assert!(
        r["targets"][0]["evidence"][0]
            .get("scanner_summary")
            .is_none()
    );
}
#[test]
fn scanner_hash_mismatch_blocks_not_reuse_an_older_file() {
    let f = Fixture::new();
    let path = f.native_report("osv-clean.json", "osv-scanner-json-v2", "Cargo.lock");
    let mut plan: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    plan["targets"][0]["required_evidence"][0]["artifact"]["sha256"] = "0".repeat(64).into();
    fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
    let output = f.cli(&path, false);
    assert_eq!(output.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        r["targets"][0]["evidence"][0]["reason"],
        "ARTIFACT_HASH_MISMATCH"
    );
}
#[test]
fn native_scanner_markdown_omits_report_payload() {
    let f = Fixture::new();
    let path = f.native_report(
        "trivy-secret.json",
        "trivy-json-v2",
        "example/app@sha256:synthetic-candidate",
    );
    let output = f.cli(&path, true);
    assert_eq!(output.status.code(), Some(2));
    let m = String::from_utf8(output.stdout).unwrap();
    assert!(m.contains("Native TrivyJsonV2: Blocked"));
    assert!(m.contains("Scanner execution NOT ATTESTED"));
    assert!(!m.contains("SYNTHETIC_RULE_ID_NO_ACTUAL_SECRET"));
}
impl Fixture {
    fn upgrade(
        &self,
        name: &str,
        scanner: &str,
        subject: &str,
        commit_override: Option<&str>,
    ) -> Output {
        let original = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/scanner")
            .join(name);
        fs::copy(original, &self.artifact).unwrap();
        let git = Command::new("git")
            .arg("-C")
            .arg(&self.repo)
            .args(["rev-parse", "refs/tags/v1.1^{commit}"])
            .output()
            .unwrap();
        assert!(git.status.success());
        let sha = String::from_utf8(git.stdout).unwrap();
        Command::new(env!("CARGO_BIN_EXE_tredven-upstream"))
            .args(["inspect-upgrade", "--repo"])
            .arg(&self.repo)
            .args([
                "--project",
                "synthetic-project",
                "--from",
                "v1.0",
                "--to",
                "v1.1",
                "--scanner",
                scanner,
                "--scan-report",
            ])
            .arg(&self.artifact)
            .args([
                "--subject",
                subject,
                "--scan-commit",
                commit_override.unwrap_or(sha.trim()),
            ])
            .output()
            .unwrap()
    }
}
#[test]
fn one_command_git_plus_trivy_critical_blocks_without_manifest() {
    let f = Fixture::new();
    let out = f.upgrade(
        "trivy-critical.json",
        "trivy-json-v2",
        "example/app@sha256:synthetic-candidate",
        None,
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        r["targets"][0]["source_inspection"]["changed_paths_considered"],
        2
    );
    assert_eq!(r["targets"][0]["decision"], "BLOCKED");
    assert_eq!(
        r["targets"][0]["evidence"][0]["scanner_summary"]["high_or_critical_occurrences"],
        1
    );
    assert_eq!(
        r["targets"][0]["evidence"][0]["candidate_binding"],
        "MATCHED"
    );
    assert_eq!(r["action_authorized"], false);
    assert_eq!(r["performed_mutations"], false);
}
#[test]
fn one_command_git_plus_trivy_clean_is_only_review() {
    let f = Fixture::new();
    let out = f.upgrade(
        "trivy-clean.json",
        "trivy-json-v2",
        "example/app@sha256:synthetic-candidate",
        None,
    );
    assert_eq!(out.status.code(), Some(0));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["targets"][0]["decision"], "REVIEW");
    assert_eq!(r["external_tool_execution_attested"], false);
    assert_eq!(r["publisher_attested"], false);
    assert_eq!(r["production_ready"], false);
}
#[test]
fn one_command_git_plus_osv_finding_blocks() {
    let f = Fixture::new();
    let out = f.upgrade(
        "osv-vulnerable.json",
        "osv-scanner-json-v2",
        "Cargo.lock",
        None,
    );
    assert_eq!(out.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["targets"][0]["decision"], "BLOCKED");
}
#[test]
fn one_command_git_plus_empty_scanner_is_unknown() {
    let f = Fixture::new();
    let out = f.upgrade("osv-empty.json", "osv-scanner-json-v2", "Cargo.lock", None);
    assert_eq!(out.status.code(), Some(3));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["targets"][0]["decision"], "UNKNOWN");
}
#[test]
fn one_command_wrong_scan_commit_cannot_be_reported_as_review() {
    let f = Fixture::new();
    let out = f.upgrade(
        "trivy-clean.json",
        "trivy-json-v2",
        "example/app@sha256:synthetic-candidate",
        Some(&"a".repeat(40)),
    );
    assert_eq!(out.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        r["targets"][0]["evidence"][0]["reason"],
        "EVIDENCE_BOUND_TO_DIFFERENT_RELEASE"
    );
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
