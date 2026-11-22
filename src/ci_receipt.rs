//! Signed CI scan-run receipts: strict source/artifact binding, not custom crypto.
//!
//! A GH-signed receipt is a *workflow claim*. Rust verifies the official
//! GH attestation, then independently matches declared scanned Git objects,
//! lockfile hashes, scanner outputs and process statuses. The signature does
//! not by itself prove a scanner ran: only reviewed, pinned CI code can lend
//! that claim operational meaning. No release or deployment authority.
use crate::PreflightReport;
use crate::attestation::{self, Policy, Verdict};
use crate::delta::{self, DeltaDecision};
use crate::git_source::git;
use crate::review::{Evidence, Report, ReviewOutput};
use crate::scanner::{self, ScanDecision, ScannerFormat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const SCHEMA: &str = "tredven.upstream.ci-osv-receipt.v1";
const SCAN_ARGS: &str =
    "scan source --lockfile Cargo.lock --format json --all-packages --no-resolve --verbosity error";
const MAX_REPORT: usize = 8 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Workflow {
    repository: String,
    repository_id: String,
    source_ref: String,
    source_commit: String,
    run_id: String,
    run_attempt: u32,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanTool {
    tool: String,
    version: String,
    binary_sha256: String,
    args: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Side {
    tag: String,
    commit: String,
    lockfile_sha256: String,
    report_sha256: String,
    exit_code: i32,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    scanned_repository: String,
    workflow: Workflow,
    scanner: ScanTool,
    baseline: Side,
    candidate: Side,
    local_scanner_processes_observed: bool,
    scan_generator: String,
}
#[derive(Debug, Serialize)]
pub struct CiReceiptEvidence {
    pub receipt_sha256: String,
    pub signer_repository: String,
    pub workflow_run_id: String,
    pub workflow_run_attempt: u32,
    pub workflow_source_commit: String,
    pub scanned_repository: String,
    pub source_commit_and_artifact_hashes_bound: bool,
    pub scanner_processes_claimed_by_submitted_receipt: bool,
    pub signed_run_receipt_accepted: bool,
    pub signed_receipt_provenance: attestation::Report,
    pub scanner_process_execution_independently_attested: bool,
}
fn sha(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn valid_digest(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())
}
fn read(path: &Path, max: usize) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "CI_RECEIPT_INPUT_NOT_FOUND")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > max as u64 {
        return Err("CI_RECEIPT_INPUT_NOT_BOUNDED_REGULAR_FILE".into());
    }
    let bytes = fs::read(path).map_err(|_| "CI_RECEIPT_INPUT_UNREADABLE")?;
    if bytes.is_empty() || bytes.len() > max {
        return Err("CI_RECEIPT_INPUT_SIZE_CHANGED".into());
    }
    Ok(bytes)
}
fn source_matches(
    side: &Side,
    expected_tag: &str,
    expected_commit: &str,
    repo: &Path,
    scan_bytes: &[u8],
) -> bool {
    if side.tag != expected_tag
        || !side.commit.eq_ignore_ascii_case(expected_commit)
        || !valid_digest(&side.lockfile_sha256)
        || !valid_digest(&side.report_sha256)
        || side.report_sha256 != sha(scan_bytes)
        || !matches!(side.exit_code, 0 | 1)
    {
        return false;
    }
    let Ok(lock) = git(repo, &["show", &format!("{expected_commit}:Cargo.lock")]) else {
        return false;
    };
    !lock.is_empty() && side.lockfile_sha256 == sha(&lock)
}
fn scan_status_matches(exit: i32, scan: &scanner::ScanSummary) -> bool {
    if scan.decision == ScanDecision::Unknown {
        return false;
    }
    (exit == 0 && scan.vulnerability_occurrences == 0)
        || (exit == 1 && scan.vulnerability_occurrences > 0)
}

/// An authoritative manifest is signed by a pinned CI workflow. The scanner
/// source repo is *not* the signing workflow repo, so don't equate their SHAs.
#[allow(clippy::too_many_arguments)]
pub fn review_signed_ci(
    repo: &Path,
    source: PreflightReport,
    project: &str,
    receipt_file: &Path,
    baseline_file: &Path,
    candidate_file: &Path,
    scanned_repo: &str,
    scanner_version: &str,
    scanner_binary_sha256: &str,
    policy: &Policy,
) -> Result<ReviewOutput, String> {
    let receipt_bytes = read(receipt_file, 64 * 1024)?;
    let parsed: Receipt = serde_json::from_slice(&receipt_bytes)
        .map_err(|_| "CI_SIGNED_RECEIPT_MALFORMED_OR_UNRECOGNIZED_SCHEMA")?;
    let baseline_bytes = read(baseline_file, MAX_REPORT)?;
    let candidate_bytes = read(candidate_file, MAX_REPORT)?;
    let base_commit = source
        .baseline_commit
        .as_deref()
        .ok_or("CI_BASELINE_COMMIT_NOT_RESOLVED")?
        .to_owned();
    let cand_commit = source
        .candidate_commit
        .as_deref()
        .ok_or("CI_CANDIDATE_COMMIT_NOT_RESOLVED")?
        .to_owned();
    // Scan report source.path may be absolute; both reports MUST refer to
    // the same scanner scope, not merely the same advisory IDs.
    let target = serde_json::from_slice::<serde_json::Value>(&baseline_bytes)
        .ok()
        .and_then(|v| {
            v["results"][0]["source"]["path"]
                .as_str()
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "Cargo.lock".into());
    let baseline =
        scanner::inspect_scanner(&baseline_bytes, ScannerFormat::OsvScannerJsonV2, &target);
    let candidate =
        scanner::inspect_scanner(&candidate_bytes, ScannerFormat::OsvScannerJsonV2, &target);
    let delta = delta::compare_reports(
        &baseline_bytes,
        &candidate_bytes,
        ScannerFormat::OsvScannerJsonV2,
        &target,
    );
    let expected_commit = &policy.source_commit;
    let claimed = parsed.schema == SCHEMA
        && parsed.scanned_repository == scanned_repo
        && parsed.workflow.repository == policy.repo
        && parsed.workflow.repository_id == policy.repository_id
        && parsed.workflow.source_ref == policy.source_ref
        && parsed.workflow.source_commit == *expected_commit
        && parsed.workflow.run_id.len() <= 24
        && !parsed.workflow.run_id.starts_with('0')
        && !parsed.workflow.run_id.is_empty()
        && parsed.workflow.run_id.bytes().all(|c| c.is_ascii_digit())
        && (1..=1000).contains(&parsed.workflow.run_attempt)
        && parsed.scanner.tool == "osv-scanner"
        && parsed.scanner.version == scanner_version
        && parsed.scanner.binary_sha256 == scanner_binary_sha256
        && valid_digest(&parsed.scanner.binary_sha256)
        && parsed.scanner.args == SCAN_ARGS
        && parsed.local_scanner_processes_observed
        && parsed.scan_generator == "tredven-upstream review-upgrade local-osv-lockfile"
        && source_matches(
            &parsed.baseline,
            &source.baseline_tag,
            &base_commit,
            repo,
            &baseline_bytes,
        )
        && source_matches(
            &parsed.candidate,
            &source.candidate_tag,
            &cand_commit,
            repo,
            &candidate_bytes,
        )
        && scan_status_matches(parsed.baseline.exit_code, &baseline)
        && scan_status_matches(parsed.candidate.exit_code, &candidate);
    // A wrong source/report hash is a declared binding contradiction, so
    // NEVER attempt to promote such a receipt via the GH verifier.
    let signature = if claimed {
        attestation::verify_artifact(receipt_file, policy)
    } else {
        attestation::reject_policy(
            policy,
            "SIGNED_CI_RUN_RECEIPT_SOURCE_OR_ARTIFACT_BINDING_MISMATCH",
        )
    };
    let expected_run = format!(
        "https://github.com/{}/actions/runs/{}/attempts/{}",
        policy.repo, parsed.workflow.run_id, parsed.workflow.run_attempt
    );
    let signed = claimed
        && signature.verdict == Verdict::Verified
        && signature.verified_workflow_run_uri.as_deref() == Some(expected_run.as_str());
    let ci = CiReceiptEvidence {
        receipt_sha256: sha(&receipt_bytes),
        signer_repository: parsed.workflow.repository,
        workflow_run_id: parsed.workflow.run_id,
        workflow_run_attempt: parsed.workflow.run_attempt,
        workflow_source_commit: parsed.workflow.source_commit,
        scanned_repository: parsed.scanned_repository,
        source_commit_and_artifact_hashes_bound: claimed,
        scanner_processes_claimed_by_submitted_receipt: parsed.local_scanner_processes_observed,
        signed_run_receipt_accepted: signed,
        signed_receipt_provenance: signature,
        scanner_process_execution_independently_attested: false,
    };
    let (decision, reason) = if !claimed {
        (
            "BLOCKED",
            "SIGNED_CI_RECEIPT_SOURCE_OR_RESULT_BINDING_MISMATCH",
        )
    } else if !signed {
        ("BLOCKED", "SIGNED_CI_RECEIPT_ATTESTATION_NOT_VERIFIED")
    } else if candidate.decision == ScanDecision::Blocked
        || delta.overall_decision == DeltaDecision::Blocked
    {
        ("BLOCKED", "VERIFIED_CI_RECEIPT_CANDIDATE_RISK_BLOCKS")
    } else if candidate.decision == ScanDecision::Unknown
        || baseline.decision == ScanDecision::Unknown
        || delta.overall_decision == DeltaDecision::Unknown
    {
        ("UNKNOWN", "SIGNED_CI_RECEIPT_SCANNER_COVERAGE_UNQUALIFIED")
    } else {
        (
            "REVIEW",
            "SIGNED_CI_RECEIPT_AND_SOURCE_BYTES_MATCH_MANUAL_REVIEW_ONLY",
        )
    };
    let report = Report {
        schema: crate::review::SCHEMA,
        project: project.to_owned(),
        source,
        scan_mode: "signed-ci-receipt",
        analyzed_lockfile: Some("Cargo.lock".into()),
        scanner_binary_sha256: Some(scanner_binary_sha256.to_owned()),
        baseline: Evidence {
            report_sha256: sha(&baseline_bytes),
            input_lockfile_sha256: Some(parsed.baseline.lockfile_sha256.clone()),
            scanner: baseline,
            local_scanner_process_exit: Some(parsed.baseline.exit_code),
            local_execution_observed: false,
            signed_file_provenance: None,
            scanner_execution_cryptographically_attested: false,
        },
        candidate: Evidence {
            report_sha256: sha(&candidate_bytes),
            input_lockfile_sha256: Some(parsed.candidate.lockfile_sha256.clone()),
            scanner: candidate,
            local_scanner_process_exit: Some(parsed.candidate.exit_code),
            local_execution_observed: false,
            signed_file_provenance: None,
            scanner_execution_cryptographically_attested: false,
        },
        delta,
        decision,
        reason,
        source_remote_publisher_attested: false,
        scanner_execution_cryptographically_attested: false,
        all_artifact_signatures_verified: false,
        signed_ci_run: Some(ci),
        public_osv_api_access_permitted: false,
        performed_git_remote_queries: false,
        performed_provider_mutations: false,
        production_ready: false,
        release_authorized: false,
        action_authorized: false,
    };
    let linked_lock = |commit: &str, digest: &str| -> Option<Vec<u8>> {
        git(repo, &["show", &format!("{commit}:Cargo.lock")])
            .ok()
            .filter(|raw| sha(raw) == digest)
    };
    let base_lock = linked_lock(&base_commit, &parsed.baseline.lockfile_sha256);
    let cand_lock = linked_lock(&cand_commit, &parsed.candidate.lockfile_sha256);
    Ok(ReviewOutput {
        report,
        baseline_json: baseline_bytes,
        candidate_json: candidate_bytes,
        baseline_lockfile: base_lock,
        candidate_lockfile: cand_lock,
        signed_ci_receipt: Some(receipt_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scanner_receipt_requires_exact_immutable_sha_digests() {
        assert!(!valid_digest("false"));
        assert!(valid_digest(&"0".repeat(64)));
        assert!(!valid_digest(&"g".repeat(64)));
    }
    #[test]
    fn zero_vulnerability_osv_finding_is_only_review_if_exit_zero() {
        let summary = scanner::inspect_scanner(
            include_bytes!("../fixtures/scanner/osv-clean.json"),
            ScannerFormat::OsvScannerJsonV2,
            "Cargo.lock",
        );
        assert_eq!(summary.decision, ScanDecision::Review);
        assert!(scan_status_matches(0, &summary));
        assert!(!scan_status_matches(1, &summary));
    }
    #[test]
    fn scanner_exit_must_agree_with_actual_finding_count() {
        let r = scanner::inspect_scanner(
            include_bytes!("../fixtures/scanner/osv-vulnerable.json"),
            ScannerFormat::OsvScannerJsonV2,
            "Cargo.lock",
        );
        assert!(scan_status_matches(1, &r));
        assert!(!scan_status_matches(0, &r));
    }
}
