//! Explicit read-only GitHub/Sigstore provenance verification.
//!
//! Cryptography, certificate chains, transparency timestamps and trust roots
//! are delegated to the official GitHub CLI. This module only constrains the
//! caller's verification policy and checks the *verified* certificate fields.
//! It never verifies or executes a scanner, triggers Actions, or grants release.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_ARTIFACT: u64 = 32 * 1024 * 1024;
const MAX_BUNDLE: u64 = 2 * 1024 * 1024;
const MAX_OUTPUT: usize = 1024 * 1024;
const SLSA: &str = "https://slsa.dev/provenance/v1";
const CYCLONEDX: &str = "https://cyclonedx.org/bom";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub repo: String,
    pub repository_id: String,
    pub signer_workflow: String,
    pub source_ref: String,
    pub source_commit: String,
    #[serde(default = "default_predicate")]
    pub predicate_type: String,
    pub bundle: Option<PathBuf>,
    pub trusted_root: Option<PathBuf>,
    #[serde(default)]
    pub online: bool,
}
fn default_predicate() -> String {
    SLSA.into()
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Verified,
    Blocked,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub verdict: Verdict,
    pub reason: &'static str,
    pub artifact_sha256: Option<String>,
    pub artifact_filename: Option<String>,
    pub repo: String,
    pub repository_id: String,
    pub signer_workflow: String,
    pub source_ref: String,
    pub source_commit: String,
    pub predicate_type: String,
    pub signatures_cryptographically_verified_by_gh: bool,
    pub validated_certificate_source_identity: bool,
    pub trusted_timestamp_observed: bool,
    pub online_attestation_lookup_requested: bool,
    pub attestation_bundle_sha256: Option<String>,
    pub trusted_root_sha256: Option<String>,
    pub trust_root_origin: &'static str,
    pub scanner_execution_verified: bool,
    pub production_ready: bool,
    pub release_authorized: bool,
    pub action_authorized: bool,
    pub performed_mutations: bool,
}
impl Report {
    fn empty(p: &Policy) -> Self {
        Self {
            schema: "tredven.upstream.gh-artifact-attestation.v1",
            verdict: Verdict::Blocked,
            reason: "VERIFICATION_NOT_PERFORMED",
            artifact_sha256: None,
            artifact_filename: None,
            repo: p.repo.clone(),
            repository_id: p.repository_id.clone(),
            signer_workflow: p.signer_workflow.clone(),
            source_ref: p.source_ref.clone(),
            source_commit: p.source_commit.clone(),
            predicate_type: p.predicate_type.clone(),
            signatures_cryptographically_verified_by_gh: false,
            validated_certificate_source_identity: false,
            trusted_timestamp_observed: false,
            online_attestation_lookup_requested: false,
            attestation_bundle_sha256: None,
            trusted_root_sha256: None,
            trust_root_origin: if p.online {
                "GITHUB_CLI_TRUST_POLICY"
            } else {
                "CALLER_SUPPLIED_TRUSTED_ROOT_NOT_INDEPENDENTLY_ATTESTED"
            },
            scanner_execution_verified: false,
            production_ready: false,
            release_authorized: false,
            action_authorized: false,
            performed_mutations: false,
        }
    }
    pub fn markdown(&self) -> String {
        format!(
            "# Cryptographically verified artifact provenance (not an upgrade approval)\n\n\
             Verdict: {:?}\nReason: {}\nArtifact: {}\nArtifact SHA-256: {}\n\
             Repository: {} (ID {})\nSigner workflow: {}\nSource: {} ({})\nPredicate: {}\n\
             Signature and trusted root verified by GitHub CLI: {}\nVerified timestamp: {}\n\
             Scanner execution: NOT VERIFIED\nRelease/deploy authority: NONE\n",
            self.verdict,
            self.reason,
            self.artifact_filename.as_deref().unwrap_or("UNKNOWN"),
            self.artifact_sha256.as_deref().unwrap_or("UNKNOWN"),
            self.repo,
            self.repository_id,
            self.signer_workflow,
            self.source_ref,
            self.source_commit,
            self.predicate_type,
            self.signatures_cryptographically_verified_by_gh,
            self.trusted_timestamp_observed
        )
    }
}

fn is_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        && s != "."
        && s != ".."
        && !s.contains("..")
}
fn sha40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn regular_bounded(path: &Path, max: u64) -> Result<Vec<u8>, &'static str> {
    let meta = fs::symlink_metadata(path).map_err(|_| "ATTESTATION_FILE_UNAVAILABLE")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > max {
        return Err("ATTESTATION_INPUT_NOT_BOUNDED_REGULAR_FILE");
    }
    let raw = fs::read(path).map_err(|_| "ATTESTATION_FILE_UNREADABLE")?;
    if raw.is_empty() || raw.len() as u64 > max {
        return Err("ATTESTATION_FILE_SIZE_CHANGED");
    }
    Ok(raw)
}
fn verify_policy(p: &Policy) -> Result<(), &'static str> {
    let mut split = p.repo.split('/');
    if !split.next().is_some_and(is_component)
        || !split.next().is_some_and(is_component)
        || split.next().is_some()
    {
        return Err("INVALID_EXACT_REPOSITORY");
    }
    if p.repository_id.is_empty()
        || p.repository_id.len() > 20
        || p.repository_id.starts_with('0')
        || !p.repository_id.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("INVALID_REPOSITORY_ID");
    }
    let prefix = format!("{}/.github/workflows/", p.repo);
    let Some(workflow) = p.signer_workflow.strip_prefix(&prefix) else {
        return Err("SIGNER_WORKFLOW_OUTSIDE_EXPECTED_REPO");
    };
    if !is_component(workflow) || !(workflow.ends_with(".yml") || workflow.ends_with(".yaml")) {
        return Err("SIGNER_WORKFLOW_UNQUALIFIED");
    }
    let ref_name = p
        .source_ref
        .strip_prefix("refs/tags/")
        .or_else(|| p.source_ref.strip_prefix("refs/heads/"))
        .ok_or("INVALID_EXACT_SOURCE_REF")?;
    if ref_name.is_empty()
        || ref_name.len() > 180
        || ref_name.starts_with('/')
        || ref_name.ends_with('/')
        || ref_name.contains("..")
        || !ref_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
    {
        return Err("INVALID_EXACT_SOURCE_REF");
    }
    if !sha40(&p.source_commit) {
        return Err("INVALID_EXACT_SOURCE_COMMIT");
    }
    if p.predicate_type != SLSA && p.predicate_type != CYCLONEDX {
        return Err("UNSUPPORTED_ATTESTATION_PREDICATE");
    }
    if p.online {
        if p.bundle.is_some() || p.trusted_root.is_some() {
            return Err("ONLINE_AND_OFFLINE_TRUST_MODE_MIXED");
        }
    } else {
        if p.bundle.is_none() || p.trusted_root.is_none() {
            return Err("OFFLINE_REQUIRES_BUNDLE_AND_TRUSTED_ROOT");
        }
    }
    Ok(())
}
fn expected_san(p: &Policy) -> String {
    format!("https://github.com/{}@{}", p.signer_workflow, p.source_ref)
}

/// Interpret ONLY JSON that the official gh CLI reports **after** successful
/// cryptographic verification; never call this on arbitrary upstream JSON.
fn verified_fields_match(output: &[u8], p: &Policy, digest: &str, filename: &str) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(output) else {
        return false;
    };
    let Some(records) = value.as_array() else {
        return false;
    };
    if records.is_empty() || records.len() > 8 {
        return false;
    }
    for item in records {
        let vr = &item["verificationResult"];
        let cert = &vr["signature"]["certificate"];
        let same_string = |key: &str, want: &str| cert[key].as_str() == Some(want);
        if !same_string(
            "sourceRepositoryURI",
            &format!("https://github.com/{}", p.repo),
        ) || !same_string("githubWorkflowRepository", &p.repo)
            || !same_string("sourceRepositoryIdentifier", &p.repository_id)
            || !same_string("sourceRepositoryRef", &p.source_ref)
            || !same_string("sourceRepositoryDigest", &p.source_commit)
            || !same_string("subjectAlternativeName", &expected_san(p))
            || !same_string("buildSignerURI", &expected_san(p))
            || !same_string("runnerEnvironment", "github-hosted")
            || vr["statement"]["predicateType"].as_str() != Some(&p.predicate_type)
            || !vr["verifiedTimestamps"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
        {
            continue;
        }
        if vr["statement"]["subject"]
            .as_array()
            .is_some_and(|subjects| {
                subjects.iter().any(|s| {
                    s["name"].as_str() == Some(filename)
                        && s["digest"]["sha256"].as_str() == Some(digest)
                })
            })
        {
            return true;
        }
    }
    false
}

pub fn verify_artifact(path: &Path, policy: &Policy) -> Report {
    let mut report = Report::empty(policy);
    if let Err(reason) = verify_policy(policy) {
        report.reason = reason;
        return report;
    }
    let filename = match path.file_name().and_then(|x| x.to_str()) {
        Some(name) if is_component(name) => name.to_string(),
        _ => {
            report.reason = "ARTIFACT_FILENAME_NOT_SAFE";
            return report;
        }
    };
    let raw = match regular_bounded(path, MAX_ARTIFACT) {
        Ok(b) => b,
        Err(reason) => {
            report.reason = reason;
            return report;
        }
    };
    let digest = format!("{:x}", Sha256::digest(&raw));
    report.artifact_sha256 = Some(digest.clone());
    report.artifact_filename = Some(filename.clone());
    if !policy.online {
        if let Some(bundle) = policy.bundle.as_ref() {
            match regular_bounded(bundle, MAX_BUNDLE) {
                Ok(bytes) => {
                    report.attestation_bundle_sha256 = Some(format!("{:x}", Sha256::digest(&bytes)))
                }
                Err(reason) => {
                    report.reason = reason;
                    return report;
                }
            }
        }
        if let Some(root) = policy.trusted_root.as_ref() {
            match regular_bounded(root, MAX_BUNDLE) {
                Ok(bytes) => {
                    report.trusted_root_sha256 = Some(format!("{:x}", Sha256::digest(&bytes)))
                }
                Err(reason) => {
                    report.reason = reason;
                    return report;
                }
            }
        }
    }
    // All gh arguments are fixed tokens or validated data. No shell, script,
    // image execution or root-privileged commands. Only *gh* does signature
    // verification; Rust must not manufacture cryptographic success.
    let mut command = Command::new("gh");
    command.args(["attestation", "verify"]).arg(path).args([
        "--repo",
        &policy.repo,
        "--signer-workflow",
        &policy.signer_workflow,
        "--source-ref",
        &policy.source_ref,
        "--source-digest",
        &policy.source_commit,
        "--predicate-type",
        &policy.predicate_type,
        "--deny-self-hosted-runners",
        "--format",
        "json",
        "--limit",
        "8",
    ]);
    if policy.online {
        // Network opt-in is deliberate; offline is the default.
        command.env("GH_HTTP_TIMEOUT", "15");
        report.online_attestation_lookup_requested = true;
    } else if let (Some(bundle), Some(root)) = (&policy.bundle, &policy.trusted_root) {
        command
            .arg("--bundle")
            .arg(bundle)
            .arg("--custom-trusted-root")
            .arg(root);
    }
    let output = match command.output() {
        Ok(o) => o,
        Err(_) => {
            report.reason = "GITHUB_CLI_NOT_AVAILABLE";
            return report;
        }
    };
    if !output.status.success() {
        report.reason = "GH_CRYPTOGRAPHIC_OR_IDENTITY_VERIFICATION_FAILED";
        return report;
    }
    if output.stdout.len() > MAX_OUTPUT {
        report.reason = "GH_VERIFICATION_OUTPUT_OVERSIZED";
        return report;
    }
    // Detect changes to the original artifact after gh read it. An attacker
    // who can mutate files is NOT prevented from changing offline trust roots.
    let after = match regular_bounded(path, MAX_ARTIFACT) {
        Ok(b) => b,
        Err(reason) => {
            report.reason = reason;
            return report;
        }
    };
    if format!("{:x}", Sha256::digest(&after)) != digest {
        report.reason = "ARTIFACT_CHANGED_DURING_VERIFICATION";
        return report;
    }
    // An offline verification must use stable, byte-identified trusted input.
    // The stored root hash is NOT authenticity, but must match the actual file
    // after the delegated GH process returns to avoid a misleading receipt.
    if !policy.online {
        let original_bundle_sha = report.attestation_bundle_sha256.clone();
        let original_root_sha = report.trusted_root_sha256.clone();
        for (path, prior) in [
            (policy.bundle.as_ref(), original_bundle_sha.as_deref()),
            (policy.trusted_root.as_ref(), original_root_sha.as_deref()),
        ] {
            let (Some(path), Some(before)) = (path, prior) else {
                report.reason = "MISSING_OFFLINE_TRUST_MATERIAL";
                return report;
            };
            match regular_bounded(path, MAX_BUNDLE) {
                Ok(raw) if format!("{:x}", Sha256::digest(&raw)) == before => {}
                _ => {
                    report.reason = "TRUST_MATERIAL_CHANGED_DURING_VERIFICATION";
                    return report;
                }
            }
        }
    }
    if !verified_fields_match(&output.stdout, policy, &digest, &filename) {
        report.reason = "VERIFIED_CERTIFICATE_OR_SUBJECT_NOT_EXPECTED";
        return report;
    }
    report.verdict = Verdict::Verified;
    report.reason = "SIGNED_ARTIFACT_PROVENANCE_AND_EXACT_IDENTITY_VERIFIED";
    report.signatures_cryptographically_verified_by_gh = true;
    report.validated_certificate_source_identity = true;
    report.trusted_timestamp_observed = true;
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p() -> Policy {
        Policy {
            repo: "demo/rust".into(),
            repository_id: "123".into(),
            signer_workflow: "demo/rust/.github/workflows/release.yml".into(),
            source_ref: "refs/tags/v1.0.0".into(),
            source_commit: "a".repeat(40),
            predicate_type: SLSA.into(),
            bundle: None,
            trusted_root: None,
            online: true,
        }
    }
    #[test]
    fn invalid_repo_and_signer_policy_fail_before_invoking_gh() {
        let mut policy = p();
        policy.repo = "bad/../path".into();
        assert_eq!(verify_policy(&policy), Err("INVALID_EXACT_REPOSITORY"));
        let mut policy = p();
        policy.signer_workflow = "other/rust/.github/workflows/release.yml".into();
        assert_eq!(
            verify_policy(&policy),
            Err("SIGNER_WORKFLOW_OUTSIDE_EXPECTED_REPO")
        );
        let mut policy = p();
        policy.source_commit = "a".repeat(39);
        assert_eq!(verify_policy(&policy), Err("INVALID_EXACT_SOURCE_COMMIT"));
    }
    #[test]
    fn missing_trust_root_must_not_become_an_online_fallback() {
        let mut policy = p();
        policy.online = false;
        assert_eq!(
            verify_policy(&policy),
            Err("OFFLINE_REQUIRES_BUNDLE_AND_TRUSTED_ROOT")
        );
        policy.online = true;
        policy.bundle = Some("/tmp/untrusted.json".into());
        assert_eq!(
            verify_policy(&policy),
            Err("ONLINE_AND_OFFLINE_TRUST_MODE_MIXED")
        );
    }
    fn synthetic_verified_record(p: &Policy) -> Value {
        serde_json::json!([{"verificationResult":{
            "signature":{"certificate":{
                "sourceRepositoryURI":format!("https://github.com/{}",p.repo),
                "githubWorkflowRepository":p.repo,
                "sourceRepositoryIdentifier":p.repository_id,
                "sourceRepositoryRef":p.source_ref,
                "sourceRepositoryDigest":p.source_commit,
                "subjectAlternativeName":expected_san(p),
                "buildSignerURI":expected_san(p),
                "runnerEnvironment":"github-hosted"}},
            "verifiedTimestamps":[{"timestamp":"synthetic-not-cryptographic"}],
            "statement":{"predicateType":SLSA,
                "subject":[{"name":"test.bin","digest":{"sha256":"b".repeat(64)}}]}}}])
    }
    #[test]
    fn parser_requires_exact_certificate_and_subject_after_gh_verification() {
        let policy = p();
        let good = synthetic_verified_record(&policy);
        let bytes = serde_json::to_vec(&good).unwrap();
        assert!(verified_fields_match(
            &bytes,
            &policy,
            &"b".repeat(64),
            "test.bin"
        ));
        assert!(!verified_fields_match(
            &bytes,
            &policy,
            &"a".repeat(64),
            "test.bin"
        ));
        assert!(!verified_fields_match(
            &bytes,
            &policy,
            &"b".repeat(64),
            "other.bin"
        ));
    }
    #[test]
    fn parser_denies_repo_id_and_runner_and_timestamp_forgery() {
        let policy = p();
        let mut obj = synthetic_verified_record(&policy);
        obj[0]["verificationResult"]["signature"]["certificate"]["sourceRepositoryIdentifier"] =
            Value::String("999".into());
        assert!(!verified_fields_match(
            &serde_json::to_vec(&obj).unwrap(),
            &policy,
            &"b".repeat(64),
            "test.bin"
        ));
        let mut obj = synthetic_verified_record(&policy);
        obj[0]["verificationResult"]["signature"]["certificate"]["runnerEnvironment"] =
            Value::String("self-hosted".into());
        assert!(!verified_fields_match(
            &serde_json::to_vec(&obj).unwrap(),
            &policy,
            &"b".repeat(64),
            "test.bin"
        ));
        let mut obj = synthetic_verified_record(&policy);
        obj[0]["verificationResult"]["verifiedTimestamps"] = serde_json::json!([]);
        assert!(!verified_fields_match(
            &serde_json::to_vec(&obj).unwrap(),
            &policy,
            &"b".repeat(64),
            "test.bin"
        ));
    }
    #[test]
    fn pure_json_is_not_an_attestation_verifier() {
        let policy = p();
        let json = serde_json::to_vec(&synthetic_verified_record(&policy)).unwrap();
        // This function is only a *post-crypto policy guard*. Supplying JSON
        // to it does not produce a Report and cannot turn on signature_verified.
        assert!(verified_fields_match(
            &json,
            &policy,
            &"b".repeat(64),
            "test.bin"
        ));
        let empty = Report::empty(&policy);
        assert!(!empty.signatures_cryptographically_verified_by_gh);
        assert!(!empty.release_authorized);
        assert!(!empty.production_ready);
    }
}
