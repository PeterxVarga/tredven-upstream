//! R11 signed CI receipt anti-forgery and reproducible evidence tests.
//! The real public source/OSV fixture is opt-in, and UNSIGNED by design.
//! No test signs, dispatches Actions, uploads data, or touches Tredven private.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
static COUNT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tredven-ci-r11-{}-{stamp}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> Option<PathBuf> {
    std::env::var_os("TREDVEN_R11_PUBLIC_REFERENCE_DIR").map(PathBuf::from)
}
fn config(src: &Path) -> Value {
    serde_json::from_slice(&fs::read(src.join("config-signed-ci-UNSIGNED-synthetic.json")).unwrap())
        .unwrap()
}
fn write_config(tmp: &Temp, payload: &Value) -> PathBuf {
    let path = tmp.0.join("config.json");
    fs::write(&path, serde_json::to_vec_pretty(payload).unwrap()).unwrap();
    path
}
fn run(path: &Path, evidence: Option<&Path>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"));
    cmd.args(["review-upgrade", "--config"]).arg(path);
    if let Some(out) = evidence {
        cmd.arg("--evidence-dir").arg(out);
    }
    cmd.output().unwrap()
}
fn read(result: &Output) -> Value {
    serde_json::from_slice(&result.stdout).unwrap_or_else(|_| {
        panic!(
            "stdout={}, stderr={}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        )
    })
}
fn copy_receipt(f: &Path, temp: &Temp) -> (Value, PathBuf) {
    let c = config(f);
    let receipt = temp.0.join("ci-run.receipt.json");
    fs::copy(f.join("ci-run.receipt.json"), &receipt).unwrap();
    (c, receipt)
}
fn mutate_receipt(path: &Path, field: &[&str], value: Value) {
    let mut r: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let mut cur = &mut r;
    for key in &field[..field.len() - 1] {
        cur = &mut cur[*key];
    }
    cur[field[field.len() - 1]] = value;
    fs::write(path, serde_json::to_vec(&r).unwrap()).unwrap();
}
#[test]
fn truly_unsigned_reference_is_source_bound_but_never_attested() {
    let Some(f) = fixture() else {
        return;
    };
    let tmp = Temp::new();
    let c = config(&f);
    let p = write_config(&tmp, &c);
    let r = run(&p, None);
    assert_eq!(
        r.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&r.stderr)
    );
    let v = read(&r);
    assert_eq!(
        v["source"]["candidate_commit"],
        "44d052afce639390846b9369be3d4ea684f4e7c4"
    );
    assert_eq!(v["delta"]["new_occurrences"], 0);
    assert_eq!(v["delta"]["persistent_occurrences"], 1);
    assert_eq!(
        v["signed_ci_run"]["source_commit_and_artifact_hashes_bound"],
        true
    );
    assert_eq!(v["signed_ci_run"]["signed_run_receipt_accepted"], false);
    assert_eq!(v["scanner_execution_cryptographically_attested"], false);
    assert_eq!(v["all_artifact_signatures_verified"], false);
    assert_eq!(v["production_ready"], false);
    assert_eq!(v["release_authorized"], false);
    assert_eq!(v["performed_provider_mutations"], false);
}
#[test]
fn fake_report_sha_blocks_even_before_external_signature_verifier() {
    let Some(f) = fixture() else {
        return;
    };
    let tmp = Temp::new();
    let (mut c, receipt) = copy_receipt(&f, &tmp);
    mutate_receipt(
        &receipt,
        &["candidate", "report_sha256"],
        json!("0".repeat(64)),
    );
    c["scan"]["receipt"] = json!(receipt);
    let result = run(&write_config(&tmp, &c), None);
    assert_eq!(result.status.code(), Some(2));
    let r = read(&result);
    assert_eq!(
        r["signed_ci_run"]["source_commit_and_artifact_hashes_bound"],
        false
    );
    assert_eq!(
        r["reason"],
        "SIGNED_CI_RECEIPT_SOURCE_OR_RESULT_BINDING_MISMATCH"
    );
}
#[test]
fn different_actual_report_bytes_rejected_despite_original_receipt() {
    let Some(f) = fixture() else {
        return;
    };
    let tmp = Temp::new();
    let mut c = config(&f);
    let artifact = tmp.0.join("candidate.scanner.json");
    let original = f.join("evidence/candidate.scanner.json");
    let mut bytes = fs::read(original).unwrap();
    bytes.push(b'\n');
    fs::write(&artifact, bytes).unwrap();
    c["scan"]["candidate"] = json!(artifact);
    let result = run(&write_config(&tmp, &c), None);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        read(&result)["signed_ci_run"]["source_commit_and_artifact_hashes_bound"],
        false
    );
}
#[test]
fn false_scanned_git_commit_rejected_without_gh_verification() {
    let Some(f) = fixture() else {
        return;
    };
    let tmp = Temp::new();
    let (mut c, receipt) = copy_receipt(&f, &tmp);
    mutate_receipt(&receipt, &["baseline", "commit"], json!("0".repeat(40)));
    c["scan"]["receipt"] = json!(receipt);
    let result = run(&write_config(&tmp, &c), None);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        read(&result)["signed_ci_run"]["source_commit_and_artifact_hashes_bound"],
        false
    );
}
#[test]
fn wrong_workflow_source_sha_does_not_ride_another_valid_signature() {
    let Some(f) = fixture() else {
        return;
    };
    let tmp = Temp::new();
    let (mut c, receipt) = copy_receipt(&f, &tmp);
    mutate_receipt(
        &receipt,
        &["workflow", "source_commit"],
        json!("f".repeat(40)),
    );
    c["scan"]["receipt"] = json!(receipt);
    let result = run(&write_config(&tmp, &c), None);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        read(&result)["reason"],
        "SIGNED_CI_RECEIPT_SOURCE_OR_RESULT_BINDING_MISMATCH"
    );
}
#[test]
fn forged_process_success_code_conflicts_with_actual_osv_findings() {
    let Some(f) = fixture() else {
        return;
    };
    let tmp = Temp::new();
    let (mut c, receipt) = copy_receipt(&f, &tmp);
    mutate_receipt(&receipt, &["candidate", "exit_code"], json!(0));
    c["scan"]["receipt"] = json!(receipt);
    let result = run(&write_config(&tmp, &c), None);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        read(&result)["signed_ci_run"]["source_commit_and_artifact_hashes_bound"],
        false
    );
}
#[test]
fn forged_signing_run_identity_fails_before_signature() {
    let Some(f) = fixture() else {
        return;
    };
    let tmp = Temp::new();
    let (mut c, receipt) = copy_receipt(&f, &tmp);
    mutate_receipt(&receipt, &["workflow", "run_id"], json!("0"));
    c["scan"]["receipt"] = json!(receipt);
    let result = run(&write_config(&tmp, &c), None);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        read(&result)["signed_ci_run"]["source_commit_and_artifact_hashes_bound"],
        false
    );
}
#[test]
fn missing_attestation_material_never_falls_back_to_online() {
    let Some(f) = fixture() else {
        return;
    };
    let tmp = Temp::new();
    let mut c = config(&f);
    c["scan"]["attestation"]["trusted_root"] = json!(tmp.0.join("absent-root.json"));
    let result = run(&write_config(&tmp, &c), None);
    assert_eq!(result.status.code(), Some(2));
    let r = read(&result);
    assert_eq!(
        r["signed_ci_run"]["signed_receipt_provenance"]["online_attestation_lookup_requested"],
        false
    );
    assert_eq!(r["signed_ci_run"]["signed_run_receipt_accepted"], false);
}
#[test]
fn evidence_bundle_carries_raw_receipt_and_exact_lockfile_bytes() {
    let Some(f) = fixture() else {
        return;
    };
    let temp = Temp::new();
    let c = config(&f);
    let p = write_config(&temp, &c);
    let output = temp.0.join("verified-claim-evidence");
    let result = run(&p, Some(&output));
    assert_eq!(result.status.code(), Some(2));
    let r = read(&result);
    assert_eq!(r["signed_ci_run"]["signed_run_receipt_accepted"], false);
    let mut names = fs::read_dir(&output)
        .unwrap()
        .map(|p| p.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    let mut expected = [
        "baseline.Cargo.lock",
        "candidate.Cargo.lock",
        "baseline.scanner.json",
        "candidate.scanner.json",
        "ci-run.receipt.json",
        "review.json",
        "SHA256SUMS",
    ]
    .to_vec();
    expected.sort();
    assert_eq!(names, expected);
    assert_eq!(
        fs::read(output.join("ci-run.receipt.json")).unwrap(),
        fs::read(f.join("ci-run.receipt.json")).unwrap()
    );
    for line in fs::read_to_string(output.join("SHA256SUMS"))
        .unwrap()
        .lines()
    {
        let (expected, file) = line.split_once("  ").unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(fs::read(output.join(file)).unwrap())),
            expected
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for file in names {
            assert_eq!(
                fs::metadata(output.join(file))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    let rerun = run(&p, Some(&output));
    assert_eq!(rerun.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rerun.stderr).contains("EVIDENCE_DIR_EXISTS_NO_OVERWRITE"));
}
#[test]
fn malformed_receipt_is_not_treated_as_signed_or_ready() {
    let Some(f) = fixture() else {
        return;
    };
    let temp = Temp::new();
    let mut c = config(&f);
    let p = temp.0.join("receipt.json");
    fs::write(&p, b"NOT-JSON").unwrap();
    c["scan"]["receipt"] = json!(p);
    let result = run(&write_config(&temp, &c), None);
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("CI_SIGNED_RECEIPT_MALFORMED"));
}
#[test]
fn manual_workflow_is_never_automatically_triggered() {
    let text = include_str!("../.github/workflows/r11-manual-public-osv-attest.yml");
    assert!(text.contains("on:\n  workflow_dispatch:"));
    assert!(!text.contains("  push:"));
    assert!(!text.contains("  pull_request:"));
    assert!(!text.contains("  schedule:"));
    assert!(text.contains("github.ref == 'refs/heads/main'"));
    assert!(text.contains("github.repository_id == 1467524521"));
    assert!(text.contains("github.event_name == 'workflow_dispatch'"));
    assert!(text.contains("steps.receipt_attestation.outputs.bundle-path"));
    assert!(text.contains("ci-run.receipt.attestation.bundle.jsonl"));
    assert!(text.contains("id-token: write"));
    assert!(text.contains("attestations: write"));
    assert!(
        text.contains("actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8")
    );
    assert!(text.contains("google/osv-scanner/releases/download/v2.7.1"));
}
