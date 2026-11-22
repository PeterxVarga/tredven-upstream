//! R10 CLI end-to-end on disposable local Git objects and synthetic reports.
//! No network/scanner execution in default tests; real public scan is opt-in
//! via TREDVEN_R10_PUBLIC_FIXTURE_CONFIG and tested separately.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
static COUNT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    dir: PathBuf,
    repo: PathBuf,
    baseline: String,
    candidate: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn git(repo: &Path, args: &[&str]) -> String {
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
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().into()
}
impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "tredven-r10-e2e-{}-{stamp}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::SeqCst)
        ));
        let repo = dir.join("source");
        fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.name", "Fixture"]);
        git(&repo, &["config", "user.email", "fixture@example.test"]);
        fs::write(repo.join("Cargo.lock"), "version = 3\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-qm", "baseline"]);
        git(&repo, &["tag", "v0.1.0"]);
        let baseline = git(&repo, &["rev-parse", "HEAD"]);
        fs::write(repo.join("Cargo.lock"), "version = 3\n# changed\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-qm", "candidate"]);
        git(&repo, &["tag", "v0.2.0"]);
        let candidate = git(&repo, &["rev-parse", "HEAD"]);
        Self {
            dir,
            repo,
            baseline,
            candidate,
        }
    }
    fn report(&self, fixture: &str, name: &str) -> PathBuf {
        let target = self.dir.join(name);
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/scanner")
                .join(fixture),
            &target,
        )
        .unwrap();
        target
    }
    fn config(&self, baseline: &Path, candidate: &Path, with_bad_attestation: bool) -> PathBuf {
        let bad_policy = json!({
            "repo":"example/fixture","repository_id":"12345",
            "signer_workflow":"example/fixture/.github/workflows/scan.yml",
            "source_ref":"refs/tags/v0.1.0",
            "source_commit":"0".repeat(40),
            "predicate_type":"https://slsa.dev/provenance/v1",
            "bundle":null,"trusted_root":null,"online":false
        });
        let mut scan = json!({
            "mode":"existing-reports","format":"trivy-json-v2",
            "subject":"example/app@sha256:synthetic-candidate",
            "baseline":baseline,"candidate":candidate
        });
        if with_bad_attestation {
            scan["baseline_attestation"] = bad_policy;
        }
        let config = json!({
            "schema":"tredven.upstream.upgrade-review.v1","project":"synthetic-public",
            "repo":self.repo,"baseline_tag":"v0.1.0","candidate_tag":"v0.2.0",
            "scan":scan
        });
        let p = self.dir.join("review-config.json");
        fs::write(&p, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        p
    }
    fn cli(&self, path: &Path, out_dir: Option<&Path>) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"));
        cmd.args(["review-upgrade", "--config"]).arg(path);
        if let Some(out) = out_dir {
            cmd.arg("--evidence-dir").arg(out);
        }
        cmd.output().unwrap()
    }
}
fn read(result: &Output) -> Value {
    serde_json::from_slice(&result.stdout)
        .unwrap_or_else(|_| panic!("non-JSON: {}", String::from_utf8_lossy(&result.stderr)))
}
#[test]
fn two_unsigned_clean_reports_do_not_yield_false_provenance_success() {
    let f = Fixture::new();
    let base = f.report("trivy-clean.json", "base.json");
    let cand = f.report("trivy-clean.json", "candidate.json");
    let cfg = f.config(&base, &cand, false);
    let result = f.cli(&cfg, None);
    assert_eq!(
        result.status.code(),
        Some(3),
        "{:?}",
        String::from_utf8_lossy(&result.stderr)
    );
    let r = read(&result);
    assert_eq!(r["decision"], "UNKNOWN");
    assert_eq!(
        r["reason"],
        "USER_SUPPLIED_REPORTS_HAVE_NO_VERIFIED_PROVENANCE"
    );
    assert_eq!(r["delta"]["new_occurrences"], 0);
    assert_eq!(r["baseline"]["local_execution_observed"], false);
    assert_eq!(r["all_artifact_signatures_verified"], false);
    assert_eq!(r["source_remote_publisher_attested"], false);
    assert_eq!(r["production_ready"], false);
    assert_eq!(r["release_authorized"], false);
}
#[test]
fn unsigned_report_with_critical_finding_still_blocks() {
    let f = Fixture::new();
    let base = f.report("trivy-clean.json", "base.json");
    let cand = f.report("trivy-critical.json", "candidate.json");
    let cfg = f.config(&base, &cand, false);
    let result = f.cli(&cfg, None);
    assert_eq!(result.status.code(), Some(2));
    let r = read(&result);
    assert_eq!(r["decision"], "BLOCKED");
    assert_eq!(r["candidate"]["scanner"]["high_or_critical_occurrences"], 1);
    assert_eq!(r["delta"]["new_occurrences"], 1);
}
#[test]
fn source_tag_mismatch_rejects_attestation_before_gh_invocation() {
    let f = Fixture::new();
    let base = f.report("trivy-clean.json", "base.json");
    let cand = f.report("trivy-clean.json", "candidate.json");
    let cfg = f.config(&base, &cand, true);
    let result = f.cli(&cfg, None);
    assert_eq!(result.status.code(), Some(2));
    let r = read(&result);
    assert_eq!(r["decision"], "BLOCKED");
    assert_eq!(
        r["baseline"]["signed_file_provenance"]["reason"],
        "ATTESTATION_SOURCE_TAG_COMMIT_NOT_THE_SELECTED_UPGRADE"
    );
    assert_eq!(
        r["baseline"]["signed_file_provenance"]["signatures_cryptographically_verified_by_gh"],
        false
    );
}
#[test]
fn explicit_evidence_directory_contains_exact_reports_checksummed_and_private() {
    let f = Fixture::new();
    let base = f.report("trivy-clean.json", "base.json");
    let cand = f.report("trivy-critical.json", "candidate.json");
    let cfg = f.config(&base, &cand, false);
    let output = f.dir.join("evidence");
    let result = f.cli(&cfg, Some(&output));
    assert_eq!(
        result.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let expected = [
        "baseline.scanner.json",
        "candidate.scanner.json",
        "review.json",
        "SHA256SUMS",
    ];
    let mut files = fs::read_dir(&output)
        .unwrap()
        .map(|x| x.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    files.sort();
    let mut want = expected.to_vec();
    want.sort();
    assert_eq!(files, want);
    let raw = fs::read(output.join("review.json")).unwrap();
    let report: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(report["decision"], "BLOCKED");
    assert_eq!(
        fs::read(output.join("baseline.scanner.json")).unwrap(),
        fs::read(base).unwrap()
    );
    let sums = fs::read_to_string(output.join("SHA256SUMS")).unwrap();
    for line in sums.lines() {
        let (want, name) = line.split_once("  ").unwrap();
        let got = format!("{:x}", Sha256::digest(fs::read(output.join(name)).unwrap()));
        assert_eq!(got, want);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in expected {
            assert_eq!(
                fs::metadata(output.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "file {name}"
            );
        }
    }
    let retry = f.cli(&cfg, Some(&output));
    assert_eq!(retry.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&retry.stderr).contains("EVIDENCE_DIR_EXISTS_NO_OVERWRITE"));
}
#[test]
fn implicit_osv_network_permission_is_rejected_before_process() {
    let f = Fixture::new();
    let p = f.dir.join("config-run.json");
    let config = json!({
        "schema":"tredven.upstream.upgrade-review.v1","project":"fixture","repo":f.repo,
        "baseline_tag":"v0.1.0","candidate_tag":"v0.2.0",
        "scan":{"mode":"local-osv-lockfile","lockfile":"Cargo.lock","binary":"/bin/false",
            "binary_sha256":"0".repeat(64),"allow_public_osv_network":false}
    });
    fs::write(&p, serde_json::to_vec(&config).unwrap()).unwrap();
    let out = f.cli(&p, None);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("OSV_PUBLIC_API_NETWORK_NOT_EXPLICITLY_APPROVED")
    );
}
#[test]
fn unrecognized_osv_binary_digest_never_executed() {
    let f = Fixture::new();
    let fake = f.dir.join("unsafe-binary");
    fs::write(&fake, b"DO_NOT_RUN").unwrap();
    let config = json!({
        "schema":"tredven.upstream.upgrade-review.v1","project":"fixture","repo":f.repo,
        "baseline_tag":"v0.1.0","candidate_tag":"v0.2.0",
        "scan":{"mode":"local-osv-lockfile","lockfile":"Cargo.lock","binary":fake,
            "binary_sha256":"0".repeat(64),"allow_public_osv_network":true}
    });
    let p = f.dir.join("bad-binary.json");
    fs::write(&p, serde_json::to_vec(&config).unwrap()).unwrap();
    let result = f.cli(&p, None);
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("SCANNER_BINARY_SHA256_MISMATCH"));
}
#[test]
fn source_repository_stays_untouched_after_evidence_checks() {
    let f = Fixture::new();
    let base = f.report("trivy-clean.json", "base.json");
    let cand = f.report("trivy-clean.json", "candidate.json");
    let cfg = f.config(&base, &cand, false);
    assert_eq!(
        git(&f.repo, &["rev-parse", "refs/tags/v0.1.0^{commit}"]),
        f.baseline
    );
    assert_eq!(
        git(&f.repo, &["rev-parse", "refs/tags/v0.2.0^{commit}"]),
        f.candidate
    );
    let original_head = git(&f.repo, &["rev-parse", "HEAD"]);
    let original_tags = git(&f.repo, &["tag", "--list"]);
    let _ = f.cli(&cfg, None);
    assert_eq!(git(&f.repo, &["rev-parse", "HEAD"]), original_head);
    assert_eq!(git(&f.repo, &["tag", "--list"]), original_tags);
    assert!(git(&f.repo, &["status", "--porcelain"]).is_empty());
}
#[test]
fn real_public_osv_scans_are_observed_if_explicitly_enabled() {
    let Some(config) = std::env::var_os("TREDVEN_R10_PUBLIC_FIXTURE_CONFIG") else {
        return;
    };
    let config = PathBuf::from(config);
    let result = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"))
        .args(["review-upgrade", "--config"])
        .arg(config)
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let r = read(&result);
    assert_eq!(r["decision"], "BLOCKED");
    assert_eq!(r["scan_mode"], "local-osv-lockfile");
    assert_eq!(r["baseline"]["local_scanner_process_exit"], 1);
    assert_eq!(r["candidate"]["local_scanner_process_exit"], 1);
    assert_eq!(r["delta"]["new_occurrences"], 0);
    assert_eq!(r["delta"]["persistent_occurrences"], 1);
    assert_eq!(r["scanner_execution_cryptographically_attested"], false);
    assert_eq!(r["production_ready"], false);
}

#[test]
fn authentic_signed_public_binary_never_passes_as_scanner_json() {
    let Some(fixture) = std::env::var_os("TREDVEN_R9_PUBLIC_FIXTURE_DIR") else {
        return;
    };
    let Some(repo) = std::env::var_os("TREDVEN_R10_PUBLIC_GIT_REPO") else {
        return;
    };
    let fixture = PathBuf::from(fixture);
    let repo = PathBuf::from(repo);
    let tmp = Fixture::new();
    let p = tmp.dir.join("signed-binary-not-scanner.json");
    let artifact = fixture.join("rust_template-0.1.0-linux-amd64");
    let bundle = fixture
        .join("sha256:e5bb76a3dcfb7faba7306c623326b8e590f023a41649e974935c41bf097475ea.jsonl");
    let policy = json!({
        "repo":"attested-delivery/rust-template", "repository_id":"1273337322",
        "signer_workflow":"attested-delivery/rust-template/.github/workflows/release.yml",
        "source_ref":"refs/tags/v0.1.0",
        "source_commit":"2b97f20f71e2b6d9c3f23ea7e968b7dd26d97e6a",
        "predicate_type":"https://slsa.dev/provenance/v1",
        "bundle":bundle,"trusted_root":fixture.join("trusted_root.jsonl"),"online":false
    });
    let config = json!({
        "schema":"tredven.upstream.upgrade-review.v1",
        "project":"public-signed-not-scanner",
        "repo":repo,"baseline_tag":"v0.1.0","candidate_tag":"v0.1.0",
        "scan":{
            "mode":"existing-reports","format":"trivy-json-v2",
            "subject":"rust_template-0.1.0-linux-amd64",
            "baseline":artifact,"candidate":artifact,
            "baseline_attestation":policy,"candidate_attestation":policy
        }
    });
    fs::write(&p, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let result = tmp.cli(&p, None);
    assert_eq!(
        result.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let r = read(&result);
    assert_eq!(r["all_artifact_signatures_verified"], true);
    assert_eq!(r["baseline"]["scanner"]["decision"], "UNKNOWN");
    assert_eq!(r["decision"], "UNKNOWN");
    assert_eq!(r["scanner_execution_cryptographically_attested"], false);
    assert_eq!(r["production_ready"], false);
}

#[test]
fn r17_first_use_never_makes_implicit_public_network_calls() {
    let f = Fixture::new();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"));
    let out = cmd
        .args(["review-local", "--repo"])
        .arg(&f.repo)
        .args([
            "--from",
            "v0.1.0",
            "--to",
            "v0.2.0",
            "--osv-bin",
            "/bin/true",
            "--osv-sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("OSV_PUBLIC_API_NETWORK_NOT_EXPLICITLY_APPROVED")
    );
}

#[test]
fn r17_first_use_preserves_exact_scanner_sha_gate() {
    let f = Fixture::new();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"));
    let out = cmd
        .args(["review-local", "--repo"])
        .arg(&f.repo)
        .args([
            "--from",
            "v0.1.0",
            "--to",
            "v0.2.0",
            "--osv-bin",
            "/bin/true",
            "--osv-sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--allow-public-osv-network",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("SCANNER_BINARY_SHA256_MISMATCH"));
}

#[test]
fn r17_first_use_refuses_duplicate_network_opt_in() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"));
    let out = cmd
        .args([
            "review-local",
            "--allow-public-osv-network",
            "--allow-public-osv-network",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("DUPLICATE_PUBLIC_OSV_NETWORK_OPT_IN"));
}

#[test]
fn r17_first_use_rejects_invalid_format_without_scan() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"));
    let out = cmd
        .args([
            "review-local",
            "--format",
            "yaml",
            "--allow-public-osv-network",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("UNSUPPORTED_FORMAT"));
}
