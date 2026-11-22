//! Upgrade evidence evaluation with explicit, read-only GitHub CLI attestation verification.
//! Most modules are local-only. The explicit attestation module delegates signed provenance verification to the official GitHub CLI; it never grants release authority.

pub mod attestation;
pub mod contract;
pub mod delta;
pub mod git_source;
pub mod plan;
pub mod scanner;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const INPUT_SCHEMA: &str = "tredven.upstream.preflight-input.v1";
pub const REPORT_SCHEMA: &str = "tredven.upstream.preflight-report.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub tag: String,
    #[serde(default)]
    pub commit: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompareCoverage {
    Complete,
    Truncated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Failed,
    NotRun,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub name: String,
    pub status: CheckStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightInput {
    pub schema: String,
    pub project: String,
    pub baseline: Release,
    pub candidate: Release,
    #[serde(default)]
    pub source_verified: Option<bool>,
    pub compare_coverage: CompareCoverage,
    #[serde(default)]
    pub changed_paths: Vec<String>,
    #[serde(default)]
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Blocked,
    Review,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authority {
    pub patch: bool,
    pub merge: bool,
    pub deploy: bool,
    pub send: bool,
    pub provider_writes: bool,
    pub paid_queries: bool,
    pub release: bool,
}

impl Authority {
    fn denied() -> Self {
        Self {
            patch: false,
            merge: false,
            deploy: false,
            send: false,
            provider_writes: false,
            paid_queries: false,
            release: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactCandidate {
    pub path: String,
    pub category: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractPrecondition {
    pub target: String,
    pub required: String,
    pub satisfied_in_snapshot: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractEvidence {
    pub profile: String,
    pub migration_path: String,
    pub pinned_migration_blob: String,
    pub schema_snapshot_origin: String,
    pub conditions: Vec<ContractPrecondition>,
    pub static_source_contract_matched: bool,
    pub real_database_checked: bool,
    pub sql_migration_executed: bool,
    pub rollback_executed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightReport {
    pub schema: String,
    /// No upstream source or runtime was contacted: input assertions are caller-supplied.
    pub evidence_origin: String,
    pub project: String,
    pub baseline_tag: String,
    pub candidate_tag: String,
    pub baseline_commit: Option<String>,
    pub candidate_commit: Option<String>,
    pub decision: Decision,
    pub source_changed: Option<bool>,
    pub compare_coverage: CompareCoverage,
    pub changed_paths_considered: usize,
    pub impact_classes: BTreeMap<String, usize>,
    pub impact_candidates: Vec<ImpactCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_evidence: Option<ContractEvidence>,
    pub checks: Vec<Check>,
    pub reasons: Vec<String>,
    pub next_action: String,
    pub production_ready: bool,
    pub authority: Authority,
}

pub fn classify_path(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower.contains("migration") || lower.contains("schema") || lower.ends_with(".sql") {
        "MIGRATION_OR_SCHEMA"
    } else if [
        "worker", "consumer", "smtp", "suppress", "campaign", "warmup", "sending",
    ]
    .iter()
    .any(|keyword| lower.contains(keyword))
    {
        "WORKER_OR_SEND_SURFACE"
    } else if ["api/", "handler", "route", "openapi", "mcp", "tool"]
        .iter()
        .any(|keyword| lower.contains(keyword))
    {
        "API_OR_CONTRACT"
    } else if [
        "go.mod",
        "go.sum",
        "package.json",
        "docker",
        "compose",
        "deploy",
        ".github/",
    ]
    .iter()
    .any(|keyword| lower.contains(keyword))
    {
        "DEPLOY_OR_DEPENDENCY"
    } else {
        "OTHER"
    }
}

fn valid_label(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
}

fn valid_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_repo_path(path: &str) -> bool {
    // Paths are classified, never opened or invoked. Real Git projects legitimately
    // contain '$', '[', ']' and Unicode filenames; reject traversal and control
    // characters rather than applying an unjustified shell-argument allowlist.
    !path.is_empty()
        && path.len() <= 2048
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

pub fn validate(input: &PreflightInput) -> Result<(), String> {
    if input.schema != INPUT_SCHEMA {
        return Err("UNSUPPORTED_INPUT_SCHEMA".into());
    }
    if !valid_label(&input.project, 80) {
        return Err("INVALID_PROJECT_ID".into());
    }
    for release in [&input.baseline, &input.candidate] {
        if !valid_label(&release.tag, 64) {
            return Err("INVALID_RELEASE_TAG".into());
        }
        if let Some(sha) = release.commit.as_deref()
            && !valid_sha(sha)
        {
            return Err("INVALID_COMMIT_ID".into());
        }
    }
    if input.changed_paths.len() > 10_000 {
        return Err("TOO_MANY_CHANGED_PATHS".into());
    }
    if input.changed_paths.iter().any(|p| !valid_repo_path(p)) {
        return Err("INVALID_SOURCE_PATH".into());
    }
    if input.checks.len() > 100 {
        return Err("TOO_MANY_CHECKS".into());
    }
    let mut unique = std::collections::BTreeSet::new();
    if input
        .checks
        .iter()
        .any(|c| !valid_label(&c.name, 80) || !unique.insert(c.name.as_str()))
    {
        return Err("INVALID_OR_DUPLICATE_CHECK".into());
    }
    Ok(())
}

pub fn inspect(input: PreflightInput) -> Result<PreflightReport, String> {
    inspect_with_origin(input, "CALLER_SUPPLIED_UNVERIFIED")
}

pub(crate) fn inspect_with_origin(
    input: PreflightInput,
    evidence_origin: &str,
) -> Result<PreflightReport, String> {
    validate(&input)?;
    let source_changed = match (
        input.baseline.commit.as_ref(),
        input.candidate.commit.as_ref(),
    ) {
        (Some(base), Some(next)) => Some(!base.eq_ignore_ascii_case(next)),
        _ => None,
    };
    let mut impact = BTreeMap::new();
    for path in &input.changed_paths {
        *impact.entry(classify_path(path).to_owned()).or_insert(0) += 1;
    }
    // A bounded sample of review candidates; paths alone never prove a breakage.
    // Match the original gate's priority ordering without claiming a risk score.
    let mut impact_candidates: Vec<ImpactCandidate> = input
        .changed_paths
        .iter()
        .filter_map(|path| {
            let category = classify_path(path);
            if category == "OTHER" {
                None
            } else {
                Some(ImpactCandidate {
                    path: path.clone(),
                    category: category.into(),
                })
            }
        })
        .collect();
    let priority = |category: &str| match category {
        "WORKER_OR_SEND_SURFACE" => 0,
        "MIGRATION_OR_SCHEMA" => 1,
        "API_OR_CONTRACT" => 2,
        "DEPLOY_OR_DEPENDENCY" => 3,
        _ => 4,
    };
    impact_candidates
        .sort_by(|a, b| (priority(&a.category), &a.path).cmp(&(priority(&b.category), &b.path)));
    impact_candidates.truncate(25);
    let mut reasons = Vec::new();
    let failed = input.checks.iter().any(|c| c.status == CheckStatus::Failed);
    if failed {
        reasons.push("MANDATORY_CHECK_FAILED".to_owned());
    }
    if input.source_verified == Some(false) {
        reasons.push("SOURCE_IDENTITY_MISMATCH".to_owned());
    }
    if source_changed == Some(false) && !input.changed_paths.is_empty() {
        reasons.push("SAME_COMMIT_WITH_REPORTED_DIFF".to_owned());
    }
    if source_changed.is_none() {
        reasons.push("MISSING_EXACT_COMMIT_COMPARISON".to_owned());
    }
    if input.source_verified.is_none() {
        reasons.push("SOURCE_IDENTITY_UNVERIFIED".to_owned());
    }
    if input.compare_coverage != CompareCoverage::Complete {
        reasons.push("DIFF_COVERAGE_INCOMPLETE".to_owned());
    }
    if input.checks.iter().any(|c| c.status != CheckStatus::Passed) {
        reasons.push("TEST_COVERAGE_INCOMPLETE".to_owned());
    }
    let blocked = failed
        || input.source_verified == Some(false)
        || (source_changed == Some(false) && !input.changed_paths.is_empty());
    let decision = if blocked {
        Decision::Blocked
    } else if input.source_verified == Some(true) && source_changed == Some(true) {
        reasons.push("UPSTREAM_SOURCE_CHANGED_REQUIRES_REVIEW".to_owned());
        Decision::Review
    } else {
        reasons.push("NO_COMPLETE_ENVIRONMENT_OR_RUNTIME_PROOF".to_owned());
        Decision::Unknown
    };
    let next_action = match decision {
        Decision::Blocked => {
            "Inspect failed check or inconsistent source evidence. Do not upgrade."
        }
        Decision::Review => {
            "Review source changes and run stack-specific isolated tests. Do not auto-upgrade."
        }
        Decision::Unknown => {
            "Obtain missing provenance and runtime test evidence. Do not auto-upgrade."
        }
    };
    Ok(PreflightReport {
        schema: REPORT_SCHEMA.into(),
        evidence_origin: evidence_origin.into(),
        project: input.project,
        baseline_tag: input.baseline.tag,
        candidate_tag: input.candidate.tag,
        baseline_commit: input.baseline.commit,
        candidate_commit: input.candidate.commit,
        decision,
        source_changed,
        compare_coverage: input.compare_coverage,
        changed_paths_considered: input.changed_paths.len(),
        impact_classes: impact,
        impact_candidates,
        contract_evidence: None,
        checks: input.checks,
        reasons,
        next_action: next_action.into(),
        production_ready: false,
        authority: Authority::denied(),
    })
}

pub fn to_markdown(r: &PreflightReport) -> String {
    let mut out = format!(
        "# Upgrade preflight — {}\n\nSource: `{}` → `{}`\n\n**Decision: {:?}**\n\nDiff coverage: {:?}; examined {} paths.\n\n",
        r.project,
        r.baseline_tag,
        r.candidate_tag,
        r.decision,
        r.compare_coverage,
        r.changed_paths_considered
    );
    out.push_str(&format!(
        "Evidence origin: `{}`\n\nCommit IDs: `{}` → `{}`\n\nLocal Git objects are not a verified upstream publisher or production runtime.\n\n",
        r.evidence_origin,
        r.baseline_commit.as_deref().unwrap_or("UNKNOWN"),
        r.candidate_commit.as_deref().unwrap_or("UNKNOWN"),
    ));
    out.push_str("## Changed surface categories\n\n");
    for (category, count) in &r.impact_classes {
        out.push_str(&format!("- {category}: {count}\n"));
    }
    out.push_str("\n## Source-path review candidates (classification only)\n\n");
    for candidate in &r.impact_candidates {
        // Use a code-span delimiter longer than any backtick run in a Git filename.
        let longest = candidate
            .path
            .split(|c| c != '`')
            .map(str::len)
            .max()
            .unwrap_or(0);
        let fence = "`".repeat(longest + 1);
        out.push_str(&format!(
            "- {}: {}{}{}\n",
            candidate.category, fence, candidate.path, fence
        ));
    }
    if let Some(contract) = &r.contract_evidence {
        out.push_str("\n## Source-bound migration contract (no SQL execution)\n\n");
        out.push_str(&format!(
            "Profile: `{}`; source migration blob: `{}`; schema source: `{}`\n\n",
            contract.profile, contract.pinned_migration_blob, contract.schema_snapshot_origin
        ));
        for condition in &contract.conditions {
            out.push_str(&format!(
                "- {}: {} → **{}**\n",
                condition.target,
                condition.required,
                if condition.satisfied_in_snapshot {
                    "MATCHED_SNAPSHOT"
                } else {
                    "MISSING_OR_INCOMPATIBLE"
                }
            ));
        }
        out.push_str("\n**Real database and migration execution: NOT TESTED.**\n");
    }
    out.push_str("\n## Missing or blocking evidence\n\n");
    for reason in &r.reasons {
        out.push_str(&format!("- {reason}\n"));
    }
    out.push_str(&format!(
        "\n## Next action\n\n{}\n\n**No deployment, patch, merge, sending or provider writes are authorized.**\n",
        r.next_action
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> PreflightInput {
        PreflightInput {
            schema: INPUT_SCHEMA.into(),
            project: "example-service".into(),
            baseline: Release {
                tag: "v1.0.0".into(),
                commit: Some("a".repeat(40)),
            },
            candidate: Release {
                tag: "v1.1.0".into(),
                commit: Some("b".repeat(40)),
            },
            source_verified: Some(true),
            compare_coverage: CompareCoverage::Complete,
            changed_paths: vec![
                "db/migrations/0002.sql".into(),
                "src/api/contracts.rs".into(),
            ],
            checks: vec![Check {
                name: "unit".into(),
                status: CheckStatus::Passed,
            }],
        }
    }

    #[test]
    fn classifies_legacy_categories() {
        assert_eq!(
            classify_path("migrations/000371.sql"),
            "MIGRATION_OR_SCHEMA"
        );
        assert_eq!(
            classify_path("internal/worker/email.go"),
            "WORKER_OR_SEND_SURFACE"
        );
        assert_eq!(classify_path("app/api/status/route.ts"), "API_OR_CONTRACT");
        assert_eq!(classify_path("Dockerfile"), "DEPLOY_OR_DEPENDENCY");
        assert_eq!(classify_path("README.md"), "OTHER");
    }

    #[test]
    fn verified_moving_source_still_needs_review() {
        let r = inspect(example()).unwrap();
        assert_eq!(r.decision, Decision::Review);
        assert!(!r.production_ready);
        assert!(!r.authority.release);
        assert!(!r.authority.send);
        assert_eq!(r.evidence_origin, "CALLER_SUPPLIED_UNVERIFIED");
        assert_eq!(r.impact_classes.get("MIGRATION_OR_SCHEMA"), Some(&1));
    }

    #[test]
    fn mismatched_source_blocks() {
        let mut x = example();
        x.source_verified = Some(false);
        assert_eq!(inspect(x).unwrap().decision, Decision::Blocked);
    }

    #[test]
    fn failed_check_blocks() {
        let mut x = example();
        x.checks[0].status = CheckStatus::Failed;
        assert_eq!(inspect(x).unwrap().decision, Decision::Blocked);
    }

    #[test]
    fn missing_provenance_is_unknown_not_pass() {
        let mut x = example();
        x.source_verified = None;
        assert_eq!(inspect(x).unwrap().decision, Decision::Unknown);
    }

    #[test]
    fn missing_commit_is_unknown_not_no_change() {
        let mut x = example();
        x.candidate.commit = None;
        assert_eq!(inspect(x).unwrap().decision, Decision::Unknown);
    }

    #[test]
    fn truncated_diff_is_explicit_even_when_reviewable() {
        let mut x = example();
        x.compare_coverage = CompareCoverage::Truncated;
        let r = inspect(x).unwrap();
        assert_eq!(r.decision, Decision::Review);
        assert!(r.reasons.contains(&"DIFF_COVERAGE_INCOMPLETE".into()));
        assert!(!r.authority.deploy);
    }

    #[test]
    fn same_commit_and_changed_paths_block() {
        let mut x = example();
        x.candidate.commit = x.baseline.commit.clone();
        assert_eq!(inspect(x).unwrap().decision, Decision::Blocked);
    }

    #[test]
    fn unchanged_source_cannot_be_release_authorized() {
        let mut x = example();
        x.candidate.commit = x.baseline.commit.clone();
        x.changed_paths.clear();
        let r = inspect(x).unwrap();
        assert_eq!(r.decision, Decision::Unknown);
        assert!(!r.authority.release);
    }

    #[test]
    fn path_traversal_is_rejected() {
        let mut x = example();
        x.changed_paths.push("../secrets.txt".into());
        assert_eq!(inspect(x).unwrap_err(), "INVALID_SOURCE_PATH");
    }

    #[test]
    fn valid_real_git_filenames_are_not_mistaken_for_shell_injection() {
        let mut x = example();
        x.changed_paths
            .push("src/routes/_app/p/$projectId/settings/integrations.tsx".into());
        x.changed_paths
            .push("web/src/routes/js/meta[.]js.ts".into());
        x.changed_paths.push("docs/árváltozás.md".into());
        assert_eq!(inspect(x).unwrap().decision, Decision::Review);
    }

    #[test]
    fn control_characters_and_absolute_paths_are_still_rejected() {
        for bad in [
            "/etc/passwd",
            "db/../passwd",
            "x/./y",
            "src/evil\\nname",
            "src/evil\\\\name",
        ] {
            let mut x = example();
            x.changed_paths.push(bad.into());
            assert_eq!(inspect(x).unwrap_err(), "INVALID_SOURCE_PATH");
        }
    }

    #[test]
    fn duplicate_check_is_rejected() {
        let mut x = example();
        x.checks.push(x.checks[0].clone());
        assert_eq!(inspect(x).unwrap_err(), "INVALID_OR_DUPLICATE_CHECK");
    }

    #[test]
    fn report_schema_is_roundtrippable() {
        let report = inspect(example()).unwrap();
        let bytes = serde_json::to_vec(&report).unwrap();
        let reread: PreflightReport = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report, reread);
        assert!(!reread.authority.provider_writes);
    }
}
