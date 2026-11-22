//! R29: verify GitHub-signed *workflow claims* for real-system integration tests.
//! No custom cryptography: reuse the existing official-gh/Sigstore verifier.
//! A verified CI run does not authorize a live upgrade or prove production safety.
use crate::attestation::{self, Policy, Verdict};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const SCHEMA: &str = "tredven.upstream.r29.signed-system-ci-manifest.v1";
const RUN_SCHEMA: &str = "tredven.upstream.r29.real-upstream-app-e2e.v1";
const TEST_SCHEMA: &str = "tredven.upstream.system-test-receipt.v1";
const MAX: u64 = 2 * 1024 * 1024;
const REQUIRED: &[(&str, &str, bool)] = &[
    ("api", "health", true),
    ("api", "integration", true),
    ("db", "health", true),
    ("db", "integration", true),
    ("db", "data-migration", true),
    ("db", "rollback", false),
    ("worker", "health", true),
    ("worker", "integration", true),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Workflow {
    repository: String,
    repository_id: String,
    signer_workflow: String,
    source_ref: String,
    source_commit: String,
    run_id: String,
    run_attempt: u32,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HashEntry {
    name: String,
    sha256: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    workflow: Workflow,
    run_evidence_sha256: String,
    rust_gate_report_sha256: String,
    receipt_hashes: Vec<HashEntry>,
    public_app_source_commit: String,
    candidate_compose_sha256: String,
    candidate_commit: String,
    test_scope: String,
}
#[derive(Serialize)]
pub struct Verification {
    pub schema: &'static str,
    pub decision: &'static str,
    pub reason: &'static str,
    pub signed_ci_provenance_verified: bool,
    pub signed_manifest_claims_match_local_receipts: bool,
    pub verified_workflow_run_uri: Option<String>,
    pub application_tests_claimed_by_ci: bool,
    pub observed_underlying_upgrade_decision: &'static str,
    pub live_upgrade_authorized: bool,
    pub production_compatibility_proven: bool,
    pub source_publisher_attested: bool,
    pub performed_provider_mutations: bool,
    pub attestation: Option<attestation::Report>,
}
fn blocked(reason: &'static str) -> Verification {
    Verification {
        schema: SCHEMA,
        decision: "BLOCKED",
        reason,
        signed_ci_provenance_verified: false,
        signed_manifest_claims_match_local_receipts: false,
        verified_workflow_run_uri: None,
        application_tests_claimed_by_ci: false,
        observed_underlying_upgrade_decision: "BLOCKED",
        live_upgrade_authorized: false,
        production_compatibility_proven: false,
        source_publisher_attested: false,
        performed_provider_mutations: false,
        attestation: None,
    }
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn valid_sha(s: &str, length: usize) -> bool {
    s.len() == length && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn bounded(path: &Path) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "CI_PROOF_FILE_MISSING")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > MAX {
        return Err("CI_PROOF_NOT_REGULAR_BOUNDED_FILE".into());
    }
    let bytes = fs::read(path).map_err(|_| "CI_PROOF_READ_FAILED")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX {
        return Err("CI_PROOF_SIZE_CHANGED".into());
    }
    Ok(bytes)
}
fn get_str<'a>(obj: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(serde_json::Value::as_str)
}
fn has_false(obj: &serde_json::Value, key: &str) -> bool {
    obj.get(key).and_then(serde_json::Value::as_bool) == Some(false)
}
fn expected_filename(s: &str) -> bool {
    REQUIRED
        .iter()
        .any(|(service, kind, _)| s == format!("receipt-{service}-{kind}.json"))
}
fn verify_local_scope(m: &Manifest, path: &Path) -> Result<(), String> {
    if m.test_scope != "REAL_API_WORKER_PG16_TO17_ROLLBACK_LOSES_CANDIDATE_WRITES"
        || m.receipt_hashes.len() != REQUIRED.len()
        || m.public_app_source_commit != "417de5b4c3e2741853944fbf97a9988de48d647d"
        || !valid_sha(&m.candidate_commit, 40)
        || !valid_sha(&m.candidate_compose_sha256, 64)
        || !valid_sha(&m.rust_gate_report_sha256, 64)
        || !valid_sha(&m.run_evidence_sha256, 64)
    {
        return Err("R29_CI_EXPECTED_REAL_APP_TEST_SCOPE_MISMATCH".into());
    }
    let mut seen = BTreeSet::new();
    for h in &m.receipt_hashes {
        if !expected_filename(&h.name) || !seen.insert(h.name.as_str()) || !valid_sha(&h.sha256, 64)
        {
            return Err("CI_PROOF_RECEIPT_HASH_DECLARATIONS_INVALID".into());
        }
    }
    let raw = bounded(&path.join("r29-local-real-app-evidence.json"))?;
    if sha(&raw) != m.run_evidence_sha256 {
        return Err("CI_RUN_REPORT_FILE_HASH_MISMATCH".into());
    }
    let run: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| "CI_RUN_REPORT_INVALID_JSON")?;
    let old = run
        .get("baseline_message_count")
        .and_then(serde_json::Value::as_u64);
    let new = run
        .get("after_upgrade_message_count")
        .and_then(serde_json::Value::as_u64);
    let recovered = run
        .get("after_rollback_message_count")
        .and_then(serde_json::Value::as_u64);
    if get_str(&run, "schema") != Some(RUN_SCHEMA)
        || get_str(&run, "app_source_commit") != Some(&m.public_app_source_commit)
        || get_str(&run, "source_fixture_candidate_commit") != Some(&m.candidate_commit)
        || get_str(&run, "candidate_compose_sha256") != Some(&m.candidate_compose_sha256)
        || get_str(&run, "result")
            != Some("REAL_APPLICATION_MIGRATION_COMPATIBLE_ROLLBACK_WITH_NEW_WRITES_BLOCKED")
        || get_str(&run, "ci_signature_provenance") != Some("UNSIGNED_LOCAL_NOT_GITHUB_HOSTED")
        || get_str(&run, "rust_gate_decision") != Some("BLOCKED")
        || !has_false(&run, "one_click_upgrade_authorized")
        || !has_false(&run, "production_ready")
        || run.get("rootless").and_then(serde_json::Value::as_bool) != Some(true)
        || run
            .get("host_ports_published")
            .and_then(serde_json::Value::as_u64)
            != Some(0)
        || run
            .get("post_cutover_new_writes_lost_on_rollback")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || old != Some(2)
        || new != Some(4)
        || recovered != old
    {
        return Err("CI_RUN_REPORT_CONTRADICTS_EXPECTED_OBSERVED_SCOPE".into());
    }
    // The 8 check file digests must match the signed manifest AND each
    // embedded source-commit/service/kind/outcome, not just a row count.
    let run_checks = run
        .get("test_receipts")
        .and_then(serde_json::Value::as_array)
        .ok_or("CI_RUN_CHECK_DECLARATIONS_MISSING")?;
    if run_checks.len() != REQUIRED.len() {
        return Err("CI_RUN_CHECK_COUNT_MISMATCH".into());
    }
    for (service, kind, must_pass) in REQUIRED {
        let filename = format!("receipt-{service}-{kind}.json");
        let binding = m
            .receipt_hashes
            .iter()
            .find(|h| h.name == filename)
            .ok_or("CI_MANIFEST_MISSING_REQUIRED_RECEIPT")?;
        let data = bounded(&path.join(&filename))?;
        if sha(&data) != binding.sha256 {
            return Err("CI_REQUIRED_RECEIPT_BYTES_CHANGED".into());
        }
        let item: serde_json::Value =
            serde_json::from_slice(&data).map_err(|_| "CI_REQUIRED_RECEIPT_INVALID_JSON")?;
        if get_str(&item, "schema") != Some(TEST_SCHEMA)
            || get_str(&item, "candidate_commit") != Some(&m.candidate_commit)
            || get_str(&item, "compose_sha256") != Some(&m.candidate_compose_sha256)
            || get_str(&item, "service") != Some(service)
            || get_str(&item, "kind") != Some(kind)
            || get_str(&item, "result") != Some(if *must_pass { "passed" } else { "failed" })
            || item.get("tests_passed").and_then(serde_json::Value::as_u64)
                != Some(u64::from(*must_pass))
            || item.get("tests_failed").and_then(serde_json::Value::as_u64)
                != Some(u64::from(!*must_pass))
            || item.get("isolated").and_then(serde_json::Value::as_bool) != Some(true)
        {
            return Err("CI_REQUIRED_CHECK_OUTCOME_OR_SOURCE_MISMATCH".into());
        }
        let claimed = run_checks
            .iter()
            .find(|e| get_str(e, "name") == Some(filename.as_str()))
            .ok_or("CI_RUN_RECEIPT_CLAIM_MISSING")?;
        if get_str(claimed, "sha256") != Some(&binding.sha256)
            || get_str(claimed, "service") != Some(service)
            || get_str(claimed, "kind") != Some(kind)
            || claimed.get("passed").and_then(serde_json::Value::as_bool) != Some(*must_pass)
        {
            return Err("CI_RUN_CLAIMED_RECEIPT_BYTES_OR_OUTCOME_MISMATCH".into());
        }
    }
    let rust = bounded(&path.join("r29-real-app-rust-gate.json"))?;
    if sha(&rust) != m.rust_gate_report_sha256 {
        return Err("CI_RUST_GATE_REPORT_HASH_MISMATCH".into());
    }
    let gate: serde_json::Value =
        serde_json::from_slice(&rust).map_err(|_| "CI_RUST_GATE_REPORT_INVALID_JSON")?;
    if get_str(&gate, "decision") != Some("BLOCKED")
        || gate
            .get("covered_required_checks")
            .and_then(serde_json::Value::as_u64)
            != Some(7)
        || gate
            .get("total_required_checks")
            .and_then(serde_json::Value::as_u64)
            != Some(8)
        || !has_false(&gate, "one_click_live_upgrade_authorized")
        || !has_false(&gate, "production_compatibility_proven")
        || gate
            .get("candidate_commit")
            .and_then(serde_json::Value::as_str)
            != Some(&m.candidate_commit)
    {
        return Err("CI_RUST_GATE_CLAIMS_INCONSISTENT".into());
    }
    Ok(())
}

pub fn verify(manifest_file: &Path, evidence_dir: &Path, policy: &Policy) -> Verification {
    let bytes = match bounded(manifest_file) {
        Ok(b) => b,
        Err(_) => return blocked("SIGNED_SYSTEM_MANIFEST_MISSING_OR_UNSAFE"),
    };
    let manifest: Manifest = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(_) => return blocked("SIGNED_SYSTEM_MANIFEST_INVALID"),
    };
    if manifest.schema != SCHEMA
        || manifest.workflow.repository != policy.repo
        || manifest.workflow.repository_id != policy.repository_id
        || manifest.workflow.signer_workflow != policy.signer_workflow
        || manifest.workflow.source_ref != policy.source_ref
        || manifest.workflow.source_commit != policy.source_commit
        || manifest.workflow.run_id.is_empty()
        || manifest.workflow.run_id.len() > 24
        || manifest.workflow.run_id.starts_with('0')
        || !manifest.workflow.run_id.bytes().all(|x| x.is_ascii_digit())
        || !(1..=1000).contains(&manifest.workflow.run_attempt)
    {
        return blocked("CI_MANIFEST_SIGNER_RUN_OR_EXACT_WORKFLOW_SOURCE_SCOPE_MISMATCH");
    }
    if verify_local_scope(&manifest, evidence_dir).is_err() {
        return blocked("CI_MANIFEST_SOURCE_TEST_RESULTS_OR_DIGEST_BINDING_MISMATCH");
    }
    // Official GitHub/Sigstore verification happens ONLY after comparing the
    // signed candidate manifest's exact source/run/receipt bytes and test scope.
    let signed = attestation::verify_artifact(manifest_file, policy);
    let expected_run = format!(
        "https://github.com/{}/actions/runs/{}/attempts/{}",
        policy.repo, manifest.workflow.run_id, manifest.workflow.run_attempt
    );
    let matched = signed.verdict == Verdict::Verified
        && signed.verified_workflow_run_uri.as_deref() == Some(expected_run.as_str())
        && signed.signatures_cryptographically_verified_by_gh
        && signed.validated_certificate_source_identity
        && signed.trusted_timestamp_observed;
    Verification {
        schema: SCHEMA,
        decision: if matched {
            "VERIFIED_CI_CLAIM"
        } else {
            "BLOCKED"
        },
        reason: if matched {
            "GH_SIGNED_RECEIPT_AND_LOCAL_EVIDENCE_MATCH_UPGRADE_STILL_BLOCKED"
        } else {
            "GITHUB_SIGNED_CI_WORKFLOW_RUN_NOT_VERIFIED"
        },
        signed_ci_provenance_verified: matched,
        signed_manifest_claims_match_local_receipts: true,
        verified_workflow_run_uri: if matched { Some(expected_run) } else { None },
        application_tests_claimed_by_ci: matched,
        observed_underlying_upgrade_decision: "BLOCKED",
        live_upgrade_authorized: false,
        production_compatibility_proven: false,
        source_publisher_attested: false,
        performed_provider_mutations: false,
        attestation: Some(signed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn required_checks_include_rollback_failure_instead_of_omitting_it() {
        assert_eq!(REQUIRED.len(), 8);
        assert_eq!(REQUIRED.iter().filter(|(_, _, passed)| !passed).count(), 1);
        assert_eq!(
            REQUIRED
                .iter()
                .find(|(_, k, _)| *k == "rollback")
                .map(|x| x.0),
            Some("db")
        );
    }
    #[test]
    fn no_unsigned_report_can_be_labeled_approved_or_verified() {
        let r = blocked("MISSING");
        assert!(!r.signed_ci_provenance_verified);
        assert!(!r.live_upgrade_authorized);
        assert!(!r.production_compatibility_proven);
        assert_eq!(r.observed_underlying_upgrade_decision, "BLOCKED");
    }
    #[test]
    fn never_trust_arbitrary_check_filename_or_digest() {
        assert!(!expected_filename("../receipt-db-rollback.json"));
        assert!(!expected_filename("receipt-db-rollback.json/.."));
        assert!(!expected_filename("receipt-worker-data-migration.json"));
        assert!(expected_filename("receipt-db-rollback.json"));
        assert!(!valid_sha("1", 64));
        assert!(!valid_sha(&"g".repeat(64), 64));
    }
}
