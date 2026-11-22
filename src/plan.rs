//! Source-only opt-in watch plans inspired by Renovate, Diun and Drydock.
//! No remote lookup, automatic update, external tool execution or approval.
use crate::git_source::inspect_local_git;
use crate::scanner::{ScanDecision, ScanSpec, ScanSummary, inspect_scanner, valid_subject};
use crate::{CheckStatus, PreflightReport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const SCHEMA: &str = "tredven.upstream.watch-plan.v1";
const MAX_ARTIFACT: u64 = 1024 * 1024;
const MAX_SCANNER_ARTIFACT: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPin {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub id: String,
    pub source_tool: String,
    pub status: CheckStatus,
    #[serde(default)]
    pub candidate_commit: Option<String>,
    #[serde(default)]
    pub artifact: Option<ArtifactPin>,
    #[serde(default)]
    pub scan: Option<ScanSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
    pub group: String,
    #[serde(default)]
    pub enabled: bool,
    pub repo: String,
    pub from_tag: String,
    pub to_tag: String,
    #[serde(default)]
    pub required_evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchPlan {
    pub schema: String,
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    Skipped,
    Blocked,
    Unknown,
    Review,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Integrity {
    Matched,
    Mismatch,
    Missing,
    Unavailable,
    InvalidPin,
    UnsafeFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateBinding {
    Matched,
    Mismatch,
    Missing,
    Unavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct Gate {
    pub id: String,
    pub source_tool: String,
    pub declared_status: CheckStatus,
    pub artifact_integrity: Integrity,
    pub candidate_binding: CandidateBinding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_summary: Option<ScanSummary>,
    pub origin: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetResult {
    pub id: String,
    pub group: String,
    pub watched: bool,
    pub decision: State,
    pub source_inspection: Option<PreflightReport>,
    pub source_error: Option<String>,
    pub evidence: Vec<Gate>,
    pub reasons: Vec<&'static str>,
    pub production_ready: bool,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct GroupSummary {
    pub skipped: usize,
    pub blocked: usize,
    pub unknown: usize,
    pub review: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub evidence_origin: &'static str,
    pub publisher_attested: bool,
    pub external_tool_execution_attested: bool,
    pub production_ready: bool,
    pub action_authorized: bool,
    pub performed_remote_queries: bool,
    pub performed_mutations: bool,
    pub targets: Vec<TargetResult>,
    pub groups: BTreeMap<String, GroupSummary>,
    pub total_watched: usize,
    pub total_skipped: usize,
    pub total_blocked: usize,
    pub total_unknown: usize,
    pub total_review: usize,
}

fn valid_id(s: &str) -> bool {
    (1..=80).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

pub fn validate(p: &WatchPlan) -> Result<(), String> {
    if p.schema != SCHEMA {
        return Err("INVALID_WATCH_PLAN_SCHEMA".into());
    }
    if p.targets.is_empty() || p.targets.len() > 32 {
        return Err("WATCH_TARGET_COUNT_OUT_OF_BOUNDS".into());
    }
    let mut ids = BTreeSet::new();
    for t in &p.targets {
        if !valid_id(&t.id) || !valid_id(&t.group) || !ids.insert(&t.id) {
            return Err("INVALID_OR_DUPLICATE_TARGET".into());
        }
        if t.enabled && t.repo.is_empty() {
            return Err("ENABLED_TARGET_REPO_REQUIRED".into());
        }
        if t.required_evidence.len() > 24 {
            return Err("EXCESS_REQUIRED_EVIDENCE".into());
        }
        let mut checks = BTreeSet::new();
        for e in &t.required_evidence {
            if e.candidate_commit
                .as_ref()
                .is_some_and(|x| x.len() != 40 || !x.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err("INVALID_CHECK_CANDIDATE_COMMIT".into());
            }
            if e.scan.as_ref().is_some_and(|scan| {
                let tool = match scan.format {
                    crate::scanner::ScannerFormat::TrivyJsonV2 => "trivy",
                    crate::scanner::ScannerFormat::OsvScannerJsonV2 => "osv-scanner",
                };
                !valid_subject(&scan.expected_subject)
                    || e.source_tool != tool
                    || e.status != CheckStatus::Unknown
            }) {
                return Err("INVALID_NATIVE_SCANNER_INPUT_CONTRACT".into());
            }
            if !valid_id(&e.id) || !valid_id(&e.source_tool) || !checks.insert(&e.id) {
                return Err("INVALID_OR_DUPLICATE_CHECK".into());
            }
        }
    }
    Ok(())
}

fn read_artifact(
    base: &Path,
    pin: Option<&ArtifactPin>,
    max_bytes: u64,
) -> (Integrity, Option<Vec<u8>>) {
    let Some(pin) = pin else {
        return (Integrity::Missing, None);
    };
    if pin.path.is_empty()
        || pin.path.len() > 2048
        || pin.sha256.len() != 64
        || !pin.sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return (Integrity::InvalidPin, None);
    }
    let file = Path::new(&pin.path);
    let full = if file.is_absolute() {
        file.to_path_buf()
    } else {
        base.join(file)
    };
    let meta = match fs::symlink_metadata(&full) {
        Ok(m) => m,
        Err(_) => return (Integrity::Unavailable, None),
    };
    if !meta.file_type().is_file() || meta.len() > max_bytes {
        return (Integrity::UnsafeFile, None);
    }
    let bytes = match fs::read(full) {
        Ok(b) => b,
        Err(_) => return (Integrity::Unavailable, None),
    };
    if bytes.len() as u64 > max_bytes {
        return (Integrity::UnsafeFile, None);
    }
    if format!("{:x}", Sha256::digest(&bytes)).eq_ignore_ascii_case(&pin.sha256) {
        (Integrity::Matched, Some(bytes))
    } else {
        (Integrity::Mismatch, None)
    }
}

fn local_path(parent: &Path, p: &str) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        parent.join(p)
    }
}

pub fn inspect_plan(plan: WatchPlan, manifest_parent: &Path) -> Result<Report, String> {
    validate(&plan)?;
    let mut r = Report {
        schema: "tredven.upstream.watch-plan-report.v1",
        evidence_origin: "LOCAL_GIT_AND_CALLER_ASSERTED_EVIDENCE",
        publisher_attested: false,
        external_tool_execution_attested: false,
        production_ready: false,
        action_authorized: false,
        performed_remote_queries: false,
        performed_mutations: false,
        targets: Vec::new(),
        groups: BTreeMap::new(),
        total_watched: 0,
        total_skipped: 0,
        total_blocked: 0,
        total_unknown: 0,
        total_review: 0,
    };
    for t in plan.targets {
        let mut x = TargetResult {
            id: t.id,
            group: t.group,
            watched: t.enabled,
            decision: State::Skipped,
            source_inspection: None,
            source_error: None,
            evidence: Vec::new(),
            reasons: Vec::new(),
            production_ready: false,
        };
        if t.enabled {
            x.decision = State::Review;
            match inspect_local_git(
                &local_path(manifest_parent, &t.repo),
                &x.id,
                &t.from_tag,
                &t.to_tag,
            ) {
                Ok(s) => {
                    if s.decision == crate::Decision::Blocked {
                        x.decision = State::Blocked;
                        x.reasons.push("SOURCE_INSPECTION_BLOCKED");
                    } else if s.decision == crate::Decision::Unknown {
                        x.decision = State::Unknown;
                        x.reasons.push("SOURCE_INSPECTION_INCOMPLETE");
                    }
                    x.source_inspection = Some(s);
                }
                Err(err) => {
                    x.decision = State::Unknown;
                    x.source_error = Some(err);
                    x.reasons.push("LOCAL_SOURCE_NOT_QUALIFIED");
                }
            }
            if t.required_evidence.is_empty() {
                if x.decision != State::Blocked {
                    x.decision = State::Unknown;
                }
                x.reasons.push("NO_REQUIRED_EVIDENCE_DECLARED");
            }
            let mut failed = false;
            let mut incomplete = false;
            let candidate = x
                .source_inspection
                .as_ref()
                .and_then(|s| s.candidate_commit.as_deref());
            for e in t.required_evidence {
                let binding = match (e.candidate_commit.as_deref(), candidate) {
                    (None, _) => CandidateBinding::Missing,
                    (Some(_), None) => CandidateBinding::Unavailable,
                    (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => CandidateBinding::Matched,
                    (Some(_), Some(_)) => CandidateBinding::Mismatch,
                };
                // Parse exactly the file bytes previously hashed and bound to
                // this source commit; a second file open would introduce TOCTOU.
                let limit = if e.scan.is_some() {
                    MAX_SCANNER_ARTIFACT
                } else {
                    MAX_ARTIFACT
                };
                let (integrity, raw) = read_artifact(manifest_parent, e.artifact.as_ref(), limit);
                let scanner_summary = match (&e.scan, raw.as_deref()) {
                    (Some(scan), Some(bytes)) if binding == CandidateBinding::Matched => {
                        Some(inspect_scanner(bytes, scan.format, &scan.expected_subject))
                    }
                    _ => None,
                };
                let (bad, missing, reason) = if e.scan.is_some() {
                    match (
                        integrity,
                        binding,
                        scanner_summary.as_ref().map(|s| s.decision),
                    ) {
                        (_, CandidateBinding::Mismatch, _) => {
                            (true, false, "EVIDENCE_BOUND_TO_DIFFERENT_RELEASE")
                        }
                        (Integrity::Mismatch, _, _) => (true, false, "ARTIFACT_HASH_MISMATCH"),
                        (
                            Integrity::Matched,
                            CandidateBinding::Matched,
                            Some(ScanDecision::Blocked),
                        ) => (true, false, "NATIVE_SCANNER_BLOCKING_FINDING"),
                        (
                            Integrity::Matched,
                            CandidateBinding::Matched,
                            Some(ScanDecision::Review),
                        ) => (false, false, "NATIVE_SCANNER_PARSED_REVIEW_ONLY"),
                        (
                            Integrity::Matched,
                            CandidateBinding::Matched,
                            Some(ScanDecision::Unknown),
                        ) => (false, true, "NATIVE_SCANNER_COVERAGE_UNKNOWN"),
                        _ => (false, true, "NATIVE_SCANNER_EVIDENCE_NOT_VERIFIED"),
                    }
                } else {
                    match (e.status, integrity, binding) {
                        (_, _, CandidateBinding::Mismatch) => {
                            (true, false, "EVIDENCE_BOUND_TO_DIFFERENT_RELEASE")
                        }
                        (_, Integrity::Mismatch, _) => (true, false, "ARTIFACT_HASH_MISMATCH"),
                        (CheckStatus::Failed, _, _) => {
                            (true, false, "REQUIRED_CHECK_REPORTED_FAILED")
                        }
                        (CheckStatus::NotRun, _, _) => (false, true, "REQUIRED_CHECK_NOT_RUN"),
                        (CheckStatus::Unknown, _, _) => (false, true, "REQUIRED_CHECK_UNKNOWN"),
                        (CheckStatus::Passed, Integrity::Matched, CandidateBinding::Matched) => {
                            (false, false, "ASSERTED_PASS_ARTIFACT_BYTES_MATCH")
                        }
                        (CheckStatus::Passed, Integrity::Matched, _) => {
                            (false, true, "PASS_NOT_BOUND_TO_SOURCE_COMMIT")
                        }
                        (CheckStatus::Passed, _, _) => {
                            (false, true, "ASSERTED_PASS_WITHOUT_INTACT_ARTIFACT")
                        }
                    }
                };
                failed |= bad;
                incomplete |= missing;
                x.evidence.push(Gate {
                    id: e.id,
                    source_tool: e.source_tool,
                    declared_status: e.status,
                    artifact_integrity: integrity,
                    candidate_binding: binding,
                    scanner_summary,
                    origin: if e.scan.is_some() {
                        "PARSED_SCANNER_JSON_TOOL_EXECUTION_NOT_ATTESTED"
                    } else {
                        "USER_DECLARED_NOT_INDEPENDENTLY_VERIFIED"
                    },
                    reason,
                });
            }
            if failed {
                x.decision = State::Blocked;
                x.reasons.push("REQUIRED_EVIDENCE_FAILED_OR_TAMPERED");
            } else if incomplete && x.decision != State::Blocked {
                x.decision = State::Unknown;
                x.reasons.push("REQUIRED_EVIDENCE_INCOMPLETE");
            }
            x.reasons
                .push("DECLARED_CHECK_SCOPE_NEVER_PROVES_PRODUCTION_READINESS");
        } else {
            x.reasons.push("WATCH_OPT_IN_DISABLED_NOT_INSPECTED");
        }
        let group = r.groups.entry(x.group.clone()).or_default();
        match x.decision {
            State::Skipped => {
                group.skipped += 1;
                r.total_skipped += 1;
            }
            State::Blocked => {
                group.blocked += 1;
                r.total_blocked += 1;
                r.total_watched += 1;
            }
            State::Unknown => {
                group.unknown += 1;
                r.total_unknown += 1;
                r.total_watched += 1;
            }
            State::Review => {
                group.review += 1;
                r.total_review += 1;
                r.total_watched += 1;
            }
        }
        r.targets.push(x);
    }
    Ok(r)
}

pub fn markdown(r: &Report) -> String {
    let mut out = format!(
        "# Read-only upstream watch plan\n\nWatched={} | Skipped={} | BLOCKED={} | UNKNOWN={} | REVIEW={}\n\n",
        r.total_watched, r.total_skipped, r.total_blocked, r.total_unknown, r.total_review,
    );
    out.push_str("Evidence from local Git and caller-supplied external tool status. SHA-256 only protects artifact bytes. No tool execution or upstream publisher attestation.\n\n");
    for x in &r.targets {
        out.push_str(&format!("## {} / {} / {:?}\n\n", x.id, x.group, x.decision));
        if let Some(s) = &x.source_inspection {
            out.push_str(&format!(
                "Local changes: {} paths, {} to {}. Not remotely attested.\n\n",
                s.changed_paths_considered, s.baseline_tag, s.candidate_tag
            ));
        }
        if let Some(e) = &x.source_error {
            out.push_str(&format!("Source error: {e}\n\n"));
        }
        for g in &x.evidence {
            out.push_str(&format!(
                "- {} from {}: {:?}, artifact {:?}, commit binding {:?}, {}\n",
                g.id,
                g.source_tool,
                g.declared_status,
                g.artifact_integrity,
                g.candidate_binding,
                g.reason
            ));
            if let Some(scan) = &g.scanner_summary {
                out.push_str(&format!(
                    "  - Native {:?}: {:?} ({}) — vulns: {}, misconfigs: {}, high/critical: {}, secrets: {}. Scanner execution NOT ATTESTED.\n",
                    scan.format,scan.decision,scan.reason,scan.vulnerability_occurrences,
                    scan.misconfiguration_occurrences,
                    scan.high_or_critical_occurrences,scan.secret_occurrences
                ));
            }
        }
        for reason in &x.reasons {
            out.push_str(&format!("- Gate: {reason}\n"));
        }
        out.push('\n');
    }
    out.push_str("No release, deploy, merge, send or provider mutation authority is granted.\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> WatchPlan {
        WatchPlan {
            schema: SCHEMA.into(),
            targets: vec![Target {
                id: "sample".into(),
                group: "ops".into(),
                enabled: false,
                repo: "/nonexistent".into(),
                from_tag: "v1".into(),
                to_tag: "v2".into(),
                required_evidence: vec![],
            }],
        }
    }
    #[test]
    fn disabled_never_inspects_repo() {
        let r = inspect_plan(sample(), Path::new("/")).unwrap();
        assert_eq!(r.total_skipped, 1);
        assert_eq!(r.total_watched, 0);
        assert_eq!(r.targets[0].decision, State::Skipped);
        assert!(!r.action_authorized);
    }
    #[test]
    fn enabled_missing_repo_is_unknown() {
        let mut p = sample();
        p.targets[0].enabled = true;
        let r = inspect_plan(p, Path::new("/")).unwrap();
        assert_eq!(r.total_unknown, 1);
        assert!(r.targets[0].source_error.is_some());
    }
    #[test]
    fn duplicate_check_and_target_rejected() {
        let mut p = sample();
        p.targets.push(p.targets[0].clone());
        assert!(validate(&p).is_err());
        let mut p = sample();
        let check = Evidence {
            id: "ci".into(),
            source_tool: "github".into(),
            status: CheckStatus::Passed,
            candidate_commit: None,
            artifact: None,
            scan: None,
        };
        p.targets[0].required_evidence = vec![check.clone(), check];
        assert!(validate(&p).is_err());
    }
    #[test]
    fn missing_artifact_never_passes() {
        assert_eq!(
            read_artifact(Path::new("/"), None, MAX_ARTIFACT).0,
            Integrity::Missing
        );
        let pin = ArtifactPin {
            path: "/not-found".into(),
            sha256: "a".repeat(64),
        };
        assert_eq!(
            read_artifact(Path::new("/"), Some(&pin), MAX_ARTIFACT).0,
            Integrity::Unavailable
        );
    }
}
