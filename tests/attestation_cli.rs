//! Release-identity contract and actual GitHub CLI verifier tests.
//!
//! All default test cases are offline/negative. The optional public fixture
//! tests only run when TREDVEN_R9_PUBLIC_FIXTURE_DIR is explicitly provided.
//! They use the real, signed public Rust-template release, NOT Tredven secrets
//! or a synthetic signature and never execute the third-party binary.
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
static COUNT: AtomicUsize = AtomicUsize::new(0);
const REPO: &str = "attested-delivery/rust-template";
const REPO_ID: &str = "1273337322";
const SIGNER: &str = "attested-delivery/rust-template/.github/workflows/release.yml";
const SOURCE_SHA: &str = "2b97f20f71e2b6d9c3f23ea7e968b7dd26d97e6a";
const FILE_SHA: &str = "e5bb76a3dcfb7faba7306c623326b8e590f023a41649e974935c41bf097475ea";
const NAME: &str = "rust_template-0.1.0-linux-amd64";

struct Temp {
    root: PathBuf,
}
impl Temp {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tredven-attestation-r9-{}-{now}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&root).unwrap();
        Self { root }
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn fixture() -> Option<PathBuf> {
    std::env::var_os("TREDVEN_R9_PUBLIC_FIXTURE_DIR").map(PathBuf::from)
}
fn run(
    mode: &str,
    artifact: &Path,
    bundle: Option<&Path>,
    root: Option<&Path>,
    alterations: &[&str],
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"));
    cmd.args([mode, "--artifact"]).arg(artifact).args([
        "--repo",
        REPO,
        "--repo-id",
        REPO_ID,
        "--signer-workflow",
        SIGNER,
        "--source-ref",
        "refs/tags/v0.1.0",
        "--source-commit",
        SOURCE_SHA,
    ]);
    if let (Some(b), Some(r)) = (bundle, root) {
        cmd.arg("--bundle").arg(b).arg("--trusted-root").arg(r);
    }
    cmd.args(alterations);
    cmd.output().unwrap()
}
fn real_files(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        root.join(NAME),
        root.join(format!("sha256:{FILE_SHA}.jsonl")),
        root.join("trusted_root.jsonl"),
    )
}
fn read(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
        panic!(
            "bad JSON: stderr={}, stdout={}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        )
    })
}
#[test]
fn missing_offline_bundle_cannot_silently_trigger_online() {
    let t = Temp::new();
    let f = t.root.join(NAME);
    fs::write(&f, b"untrusted").unwrap();
    let r = run("verify-attestation", &f, None, None, &[]);
    assert_eq!(r.status.code(), Some(2));
    let json = read(&r);
    assert_eq!(json["verdict"], "BLOCKED");
    assert_eq!(json["reason"], "OFFLINE_REQUIRES_BUNDLE_AND_TRUSTED_ROOT");
    assert_eq!(json["online_attestation_lookup_requested"], false);
}
#[test]
fn duplicate_commit_arguments_are_rejected_before_gh_invocation() {
    let t = Temp::new();
    let f = t.root.join(NAME);
    fs::write(&f, b"untrusted").unwrap();
    let r = run(
        "verify-attestation",
        &f,
        None,
        None,
        &["--source-commit", "000"],
    );
    assert_eq!(r.status.code(), Some(1)); // duplicate args are rejected
    assert!(String::from_utf8(r.stderr).unwrap().contains("DUPLICATE"));
}
#[test]
fn untrusted_input_symlink_is_not_followed() {
    #[cfg(unix)]
    {
        let t = Temp::new();
        let f = t.root.join(NAME);
        fs::write(&f, b"untrusted").unwrap();
        let alias = t.root.join("alias.bin");
        std::os::unix::fs::symlink(&f, &alias).unwrap();
        let bundle = t.root.join("bundle.json");
        let root = t.root.join("root.json");
        fs::write(&bundle, b"fake-bundle").unwrap();
        fs::write(&root, b"fake-root").unwrap();
        let r = run(
            "verify-attestation",
            &alias,
            Some(&bundle),
            Some(&root),
            &[],
        );
        assert_eq!(r.status.code(), Some(2));
        let j = read(&r);
        assert_eq!(j["reason"], "ATTESTATION_INPUT_NOT_BOUNDED_REGULAR_FILE");
    }
}
#[test]
fn public_signed_release_with_pinned_identity_is_verified_offline() {
    let Some(f) = fixture() else {
        return;
    };
    let (artifact, bundle, root) = real_files(&f);
    let output = run(
        "verify-attestation",
        &artifact,
        Some(&bundle),
        Some(&root),
        &[],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let r = read(&output);
    assert_eq!(r["verdict"], "VERIFIED");
    assert_eq!(r["artifact_sha256"], FILE_SHA);
    assert_eq!(r["repository_id"], REPO_ID);
    assert_eq!(r["signatures_cryptographically_verified_by_gh"], true);
    assert_eq!(r["online_attestation_lookup_requested"], false);
    assert_eq!(r["scanner_execution_verified"], false);
    assert_eq!(r["production_ready"], false);
}
#[test]
fn real_signed_binary_is_not_a_signed_scanner_result() {
    let Some(f) = fixture() else {
        return;
    };
    let (artifact, bundle, root) = real_files(&f);
    let output = run(
        "inspect-attested-scan",
        &artifact,
        Some(&bundle),
        Some(&root),
        &["--scanner", "trivy-json-v2", "--subject", NAME],
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let r = read(&output);
    assert_eq!(r["attestation"]["verdict"], "VERIFIED");
    assert_eq!(r["scanner_summary"]["decision"], "UNKNOWN");
    assert_eq!(r["scanner_execution_verified"], false);
    assert_eq!(r["production_ready"], false);
}
#[test]
fn tampered_authentic_signed_release_cannot_be_verified() {
    let Some(f) = fixture() else {
        return;
    };
    let (artifact, bundle, root) = real_files(&f);
    let tmp = Temp::new();
    let bad = tmp.root.join(NAME);
    fs::copy(artifact, &bad).unwrap();
    let mut file = fs::OpenOptions::new().append(true).open(&bad).unwrap();
    use std::io::Write;
    file.write_all(b"TAMPERED").unwrap();
    let output = run("verify-attestation", &bad, Some(&bundle), Some(&root), &[]);
    assert_eq!(output.status.code(), Some(2));
    let j = read(&output);
    assert_eq!(j["verdict"], "BLOCKED");
    assert_eq!(j["signatures_cryptographically_verified_by_gh"], false);
}
#[test]
fn swapped_repo_id_does_not_pass_real_signature_validation() {
    let Some(f) = fixture() else {
        return;
    };
    let (artifact, bundle, root) = real_files(&f);
    // Valid signature, but caller expects the wrong immutable repository ID.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"));
    cmd.args(["verify-attestation", "--artifact"])
        .arg(artifact)
        .args([
            "--repo",
            REPO,
            "--repo-id",
            "9999999999",
            "--signer-workflow",
            SIGNER,
            "--source-ref",
            "refs/tags/v0.1.0",
            "--source-commit",
            SOURCE_SHA,
            "--bundle",
        ])
        .arg(bundle)
        .arg("--trusted-root")
        .arg(root);
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        read(&out)["reason"],
        "VERIFIED_CERTIFICATE_OR_SUBJECT_NOT_EXPECTED"
    );
}

#[test]
fn valid_signature_cannot_be_repurposed_for_different_artifact_name() {
    let Some(f) = fixture() else {
        return;
    };
    let (artifact, bundle, root) = real_files(&f);
    let temp = Temp::new();
    let other = temp.root.join("renamed-public-release.bin");
    fs::copy(&artifact, &other).unwrap();
    let out = run(
        "verify-attestation",
        &other,
        Some(&bundle),
        Some(&root),
        &[],
    );
    assert_eq!(out.status.code(), Some(2));
    let result = read(&out);
    assert_eq!(result["verdict"], "BLOCKED");
    assert_eq!(
        result["reason"],
        "VERIFIED_CERTIFICATE_OR_SUBJECT_NOT_EXPECTED"
    );
}
#[test]
fn altered_real_bundle_cannot_be_reaccepted_as_valid_signature() {
    let Some(f) = fixture() else {
        return;
    };
    let (artifact, _bundle, root) = real_files(&f);
    let temp = Temp::new();
    let corrupted = temp.root.join("bundle.jsonl");
    fs::write(&corrupted, br#"{"fake":true}"#).unwrap();
    let out = run(
        "verify-attestation",
        &artifact,
        Some(&corrupted),
        Some(&root),
        &[],
    );
    assert_eq!(out.status.code(), Some(2));
    let result = read(&out);
    assert_eq!(result["verdict"], "BLOCKED");
    assert_eq!(result["signatures_cryptographically_verified_by_gh"], false);
}
#[test]
fn changed_root_fails_and_cannot_fallback_online() {
    let Some(f) = fixture() else {
        return;
    };
    let (artifact, bundle, _) = real_files(&f);
    let temp = Temp::new();
    let replaced = temp.root.join("root.jsonl");
    fs::write(&replaced, br#"{"fake":true}"#).unwrap();
    let out = run(
        "verify-attestation",
        &artifact,
        Some(&bundle),
        Some(&replaced),
        &[],
    );
    assert_eq!(out.status.code(), Some(2));
    let result = read(&out);
    assert_eq!(result["verdict"], "BLOCKED");
    assert_eq!(result["online_attestation_lookup_requested"], false);
}
#[test]
fn invalid_source_pin_fails_closed_before_any_attestation_lookup() {
    let Some(f) = fixture() else {
        return;
    };
    let (artifact, bundle, root) = real_files(&f);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"));
    cmd.args(["verify-attestation", "--artifact"])
        .arg(artifact)
        .args([
            "--repo",
            REPO,
            "--repo-id",
            REPO_ID,
            "--signer-workflow",
            SIGNER,
            "--source-ref",
            "refs/tags/v0.1.0",
            "--source-commit",
            "bad-sha",
            "--bundle",
        ])
        .arg(bundle)
        .arg("--trusted-root")
        .arg(root);
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(read(&out)["reason"], "INVALID_EXACT_SOURCE_COMMIT");
}
#[test]
fn unsigned_local_r8_candidate_cannot_be_accepted_under_another_repos_signature() {
    let Some(f) = fixture() else {
        return;
    };
    let (_, bundle, root) = real_files(&f);
    let pkg = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "output/r8-046a62c-offline-local/tredven-upstream-v0.1.0-x86_64-unknown-linux-gnu.tar.gz",
    );
    if !pkg.exists() {
        return;
    }
    let tmp = Temp::new();
    let fake = tmp.root.join(NAME);
    fs::copy(&pkg, &fake).unwrap();
    let out = run("verify-attestation", &fake, Some(&bundle), Some(&root), &[]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(read(&out)["verdict"], "BLOCKED");
}

#[test]
fn reusable_json_policy_verifies_real_public_release_offline() {
    let Some(f) = fixture() else {
        return;
    };
    let (artifact, _, _) = real_files(&f);
    let policy = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/r9-public-attestation-policy.example.json");
    let out = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"))
        .args(["verify-attestation", "--artifact"])
        .arg(artifact)
        .arg("--policy")
        .arg(policy)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = read(&out);
    assert_eq!(r["verdict"], "VERIFIED");
    assert_eq!(r["online_attestation_lookup_requested"], false);
    assert_eq!(
        r["trust_root_origin"],
        "CALLER_SUPPLIED_TRUSTED_ROOT_NOT_INDEPENDENTLY_ATTESTED"
    );
    assert_eq!(r["trusted_root_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(r["release_authorized"], false);
}
#[test]
fn owner_json_policy_cannot_be_silently_mixed_with_online_mode() {
    let temp = Temp::new();
    let artifact = temp.root.join("fixture.bin");
    fs::write(&artifact, b"synthetic").unwrap();
    let policy = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/r9-public-attestation-policy.example.json");
    let out = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"))
        .args(["verify-attestation", "--artifact"])
        .arg(artifact)
        .arg("--policy")
        .arg(policy)
        .arg("--online")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("ATTESTATION_POLICY_SOURCE_CONFLICT"));
}
#[test]
fn symlinked_policy_file_is_rejected_before_any_gh_verification() {
    #[cfg(unix)]
    {
        let temp = Temp::new();
        let artifact = temp.root.join("synthetic.bin");
        fs::write(&artifact, b"synthetic").unwrap();
        let policy = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples/r9-public-attestation-policy.example.json");
        let link = temp.root.join("policy-link.json");
        std::os::unix::fs::symlink(policy, &link).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"))
            .args(["verify-attestation", "--artifact"])
            .arg(artifact)
            .arg("--policy")
            .arg(link)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .contains("ATTESTATION_POLICY_NOT_BOUNDED_REGULAR_FILE")
        );
    }
}
