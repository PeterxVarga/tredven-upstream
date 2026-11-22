//! Compare two existing scanner JSON reports without running either scanner.
//!
//! Finding identity is exact and conservative. A vulnerability that survives an
//! upgrade remains an *absolute* blocker even if the delta has no new issues.
use crate::scanner::{ScanDecision, ScanSummary, ScannerFormat, inspect_scanner, valid_subject};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const SCHEMA: &str = "tredven.upstream.scan-delta.v1";
const MAX_ITEMS: usize = 20_000;
const MAX_SAMPLES: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeltaDecision {
    Blocked,
    Unknown,
    Review,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FindingKey {
    category: &'static str,
    target: String,
    package: String,
    id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NewFinding {
    pub category: &'static str,
    pub package: String,
    pub id: String,
    pub severity: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
    Advisory,
    Secret,
}
impl Severity {
    fn label(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
            Self::Advisory => "ADVISORY",
            Self::Secret => "SECRET",
        }
    }
    fn blocking(self) -> bool {
        matches!(
            self,
            Self::High | Self::Critical | Self::Advisory | Self::Secret
        )
    }
    fn priority(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
            Self::Advisory | Self::Secret => 4,
        }
    }
}

#[derive(Debug)]
struct ScanEntries {
    targets: BTreeSet<String>,
    findings: BTreeMap<FindingKey, Severity>,
}

fn clean_id(value: &Value, key: &str) -> Result<String, &'static str> {
    let s = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or("MISSING_FINDING_IDENTITY")?;
    if s.is_empty() || s.len() > 160 || s.chars().any(char::is_control) {
        return Err("INVALID_FINDING_IDENTITY");
    }
    Ok(s.into())
}
fn parse_severity(value: &Value) -> Severity {
    match value.get("Severity").and_then(Value::as_str) {
        Some("LOW") => Severity::Low,
        Some("MEDIUM") => Severity::Medium,
        Some("HIGH") => Severity::High,
        Some("CRITICAL") => Severity::Critical,
        _ => Severity::Unknown,
    }
}

fn insert(
    entries: &mut ScanEntries,
    category: &'static str,
    target: &str,
    package: String,
    id: String,
    severity: Severity,
) -> Result<(), &'static str> {
    if entries.findings.len() >= MAX_ITEMS {
        return Err("TOO_MANY_FINDINGS");
    }
    let key = FindingKey {
        category,
        target: target.into(),
        package,
        id,
    };
    entries
        .findings
        .entry(key)
        .and_modify(|old| {
            if severity.priority() > old.priority() {
                *old = severity;
            }
        })
        .or_insert(severity);
    Ok(())
}

fn parse_entries(raw: &[u8], format: ScannerFormat) -> Result<ScanEntries, &'static str> {
    let value: Value = serde_json::from_slice(raw).map_err(|_| "INVALID_SCANNER_JSON")?;
    let mut out = ScanEntries {
        targets: BTreeSet::new(),
        findings: BTreeMap::new(),
    };
    match format {
        ScannerFormat::TrivyJsonV2 => {
            let results = value
                .get("Results")
                .and_then(Value::as_array)
                .ok_or("TRIVY_RESULTS_UNQUALIFIED")?;
            if results.is_empty() || results.len() > MAX_ITEMS {
                return Err("TRIVY_RESULT_SCOPE_UNKNOWN");
            }
            for result in results {
                let target = clean_id(result, "Target")?;
                // Trivy may return distinct vulnerability, secret and
                // misconfiguration scanners for one logical target. Compare
                // *identical scanner scopes*, not just target name.
                let class = result.get("Class").and_then(Value::as_str).unwrap_or("");
                let kind = result.get("Type").and_then(Value::as_str).unwrap_or("");
                if class.len() > 80
                    || kind.len() > 80
                    || class.chars().any(char::is_control)
                    || kind.chars().any(char::is_control)
                {
                    return Err("TRIVY_SCANNER_SCOPE_INVALID");
                }
                let vuln_field = result.get("Vulnerabilities");
                let misconfig_field = result.get("Misconfigurations");
                let secret_field = result.get("Secrets");
                for field in [vuln_field, misconfig_field, secret_field]
                    .into_iter()
                    .flatten()
                {
                    if !field.is_array() {
                        return Err("TRIVY_SCANNER_RESULT_ARRAY_INVALID");
                    }
                }
                if vuln_field.is_none() && misconfig_field.is_none() && secret_field.is_none() {
                    return Err("TRIVY_SCANNER_SCOPE_NOT_DECLARED");
                }
                let scope = format!(
                    "{target}\0{class}\0{kind}\0{}{}{}",
                    u8::from(vuln_field.is_some()),
                    u8::from(misconfig_field.is_some()),
                    u8::from(secret_field.is_some())
                );
                if !out.targets.insert(scope.clone()) {
                    return Err("DUPLICATE_TRIVY_SCANNER_SCOPE");
                }
                if let Some(vulns) = vuln_field.and_then(Value::as_array) {
                    for v in vulns {
                        insert(
                            &mut out,
                            "vulnerability",
                            &scope,
                            clean_id(v, "PkgName")?,
                            clean_id(v, "VulnerabilityID")?,
                            parse_severity(v),
                        )?;
                    }
                }
                for (key, category, id_field) in [
                    ("Misconfigurations", "misconfiguration", "ID"),
                    ("Secrets", "secret", "RuleID"),
                ] {
                    if let Some(items) = result.get(key) {
                        let array = items.as_array().ok_or("TRIVY_FINDING_ARRAY_MALFORMED")?;
                        for item in array {
                            let id = clean_id(item, id_field)?;
                            let severity = if category == "secret" {
                                Severity::Secret
                            } else {
                                parse_severity(item)
                            };
                            insert(&mut out, category, &scope, String::new(), id, severity)?;
                        }
                    }
                }
            }
        }
        ScannerFormat::OsvScannerJsonV2 => {
            let results = value
                .get("results")
                .and_then(Value::as_array)
                .ok_or("OSV_RESULTS_UNQUALIFIED")?;
            if results.is_empty() || results.len() > MAX_ITEMS {
                return Err("OSV_PACKAGE_SCOPE_UNKNOWN");
            }
            for result in results {
                let source = result.get("source").ok_or("OSV_SOURCE_MISSING")?;
                let target = clean_id(source, "path")?;
                let source_type = clean_id(source, "type")?;
                let scope = format!("{target}\0{source_type}");
                out.targets.insert(scope.clone());
                let packages = result
                    .get("packages")
                    .and_then(Value::as_array)
                    .ok_or("OSV_PACKAGES_UNQUALIFIED")?;
                if packages.is_empty() {
                    return Err("OSV_ZERO_PACKAGES");
                }
                for p in packages {
                    let meta = p.get("package").ok_or("OSV_PACKAGE_MISSING")?;
                    let name = clean_id(meta, "name")?;
                    let _version = clean_id(meta, "version")?;
                    let ecosystem = clean_id(meta, "ecosystem")?;
                    // Native OSV --all-packages omits vulnerabilities
                    // altogether for clean packages. Keep malformed nonarray
                    // values invalid; an absent array is just zero reported.
                    let vulnerabilities = match p.get("vulnerabilities") {
                        None => None,
                        Some(Value::Array(v)) => Some(v),
                        Some(_) => return Err("OSV_VULNERABILITIES_NOT_ARRAY"),
                    };
                    for vuln in vulnerabilities.into_iter().flatten() {
                        insert(
                            &mut out,
                            "advisory",
                            &scope,
                            format!("{ecosystem}/{name}"),
                            clean_id(vuln, "id")?,
                            Severity::Advisory,
                        )?;
                    }
                }
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Serialize)]
pub struct ScanDeltaReport {
    pub schema: &'static str,
    pub format: ScannerFormat,
    pub subject: String,
    pub baseline: ScanSummary,
    pub candidate: ScanSummary,
    pub baseline_report_sha256: String,
    pub candidate_report_sha256: String,
    pub identical_report_bytes: bool,
    pub comparable_scan_scope: bool,
    pub delta_decision: DeltaDecision,
    pub overall_decision: DeltaDecision,
    pub reason: &'static str,
    pub new_occurrences: Option<usize>,
    pub resolved_occurrences: Option<usize>,
    pub persistent_occurrences: Option<usize>,
    pub severity_escalations: Option<usize>,
    pub new_blocking_occurrences: Option<usize>,
    pub new_sample: Vec<NewFinding>,
    pub findings_sample_truncated: bool,
    pub origin: &'static str,
    pub scanner_execution_attested: bool,
    pub baseline_source_commit_attested: bool,
    pub candidate_source_commit_attested: bool,
    pub remote_publisher_attested: bool,
    pub production_ready: bool,
    pub action_authorized: bool,
    pub performed_remote_queries: bool,
    pub performed_mutations: bool,
}
impl ScanDeltaReport {
    pub fn to_markdown(&self) -> String {
        let mut s = format!(
            "# Upgrade risk delta — read-only\n\nScanner: {:?}\nSubject: {}\nBaseline: {:?}; Candidate: {:?}\nDelta: {:?}; Overall: {:?}\nReason: {}\n\n",
            self.format,
            self.subject,
            self.baseline.decision,
            self.candidate.decision,
            self.delta_decision,
            self.overall_decision,
            self.reason
        );
        if let (Some(new), Some(resolved), Some(persistent)) = (
            self.new_occurrences,
            self.resolved_occurrences,
            self.persistent_occurrences,
        ) {
            s.push_str(&format!(
                "New: {}; Resolved: {}; Persistent: {}; Severity escalations: {}; New blockers: {}\n\n",
                new,resolved,persistent,self.severity_escalations.unwrap_or(0),
                self.new_blocking_occurrences.unwrap_or(0)
            ));
            for f in &self.new_sample {
                s.push_str(&format!(
                    "- New {} {} [{}] ({})\n",
                    f.category, f.id, f.package, f.severity
                ));
            }
            if self.findings_sample_truncated {
                s.push_str("- More new findings omitted\n");
            }
        } else {
            s.push_str("Delta counts: UNKNOWN — scanner scope not comparable\n");
        }
        s.push_str("\nScanner execution, source-to-report binding and remote publisher identity NOT ATTESTED. Existing candidate blockers remain BLOCKED even if the delta has no new findings. No upgrade authority.\n");
        s
    }
}

pub fn compare_reports(
    baseline_bytes: &[u8],
    candidate_bytes: &[u8],
    format: ScannerFormat,
    subject: &str,
) -> ScanDeltaReport {
    let baseline = inspect_scanner(baseline_bytes, format, subject);
    let candidate = inspect_scanner(candidate_bytes, format, subject);
    let mut out = ScanDeltaReport {
        schema: SCHEMA,
        format,
        subject: subject.into(),
        baseline,
        candidate,
        baseline_report_sha256: format!("{:x}", Sha256::digest(baseline_bytes)),
        candidate_report_sha256: format!("{:x}", Sha256::digest(candidate_bytes)),
        identical_report_bytes: baseline_bytes == candidate_bytes,
        comparable_scan_scope: false,
        delta_decision: DeltaDecision::Unknown,
        overall_decision: DeltaDecision::Unknown,
        reason: "SCANNER_REPORT_SCOPE_NOT_COMPARABLE",
        new_occurrences: None,
        resolved_occurrences: None,
        persistent_occurrences: None,
        severity_escalations: None,
        new_blocking_occurrences: None,
        new_sample: Vec::new(),
        findings_sample_truncated: false,
        origin: "LOCAL_UNATTESTED_SCANNER_JSON",
        scanner_execution_attested: false,
        baseline_source_commit_attested: false,
        candidate_source_commit_attested: false,
        remote_publisher_attested: false,
        production_ready: false,
        action_authorized: false,
        performed_remote_queries: false,
        performed_mutations: false,
    };
    if !valid_subject(subject)
        || baseline_bytes.len() > 8 * 1024 * 1024
        || candidate_bytes.len() > 8 * 1024 * 1024
        || out.baseline.decision == ScanDecision::Unknown
        || out.candidate.decision == ScanDecision::Unknown
    {
        out.reason = "SCAN_REPORT_INCOMPLETE_OR_UNSUPPORTED";
    } else {
        match (
            parse_entries(baseline_bytes, format),
            parse_entries(candidate_bytes, format),
        ) {
            (Ok(before), Ok(after)) if before.targets == after.targets => {
                out.comparable_scan_scope = true;
                let mut new = 0usize;
                let mut persistent = 0usize;
                let mut escalations = 0usize;
                let mut new_blocking = 0usize;
                for (key, severity) in &after.findings {
                    if let Some(old) = before.findings.get(key) {
                        persistent += 1;
                        if severity.priority() > old.priority() {
                            escalations += 1;
                            if severity.blocking() {
                                new_blocking += 1;
                            }
                        }
                    } else {
                        new += 1;
                        if severity.blocking() {
                            new_blocking += 1;
                        }
                        if out.new_sample.len() < MAX_SAMPLES {
                            out.new_sample.push(NewFinding {
                                category: key.category,
                                package: key.package.clone(),
                                id: key.id.clone(),
                                severity: severity.label(),
                            });
                        }
                    }
                }
                out.new_occurrences = Some(new);
                out.resolved_occurrences = Some(
                    before
                        .findings
                        .keys()
                        .filter(|k| !after.findings.contains_key(*k))
                        .count(),
                );
                out.persistent_occurrences = Some(persistent);
                out.severity_escalations = Some(escalations);
                out.new_blocking_occurrences = Some(new_blocking);
                out.findings_sample_truncated = new > out.new_sample.len();
                out.delta_decision = if new_blocking > 0 {
                    DeltaDecision::Blocked
                } else {
                    DeltaDecision::Review
                };
                out.reason = if new_blocking > 0 {
                    "NEW_OR_ESCALATED_BLOCKING_FINDING"
                } else {
                    "NO_NEW_BLOCKING_FINDINGS_IN_COMPARABLE_SCOPE"
                };
            }
            (Ok(_), Ok(_)) => out.reason = "SCANNER_TARGET_SETS_DIFFER_CANNOT_COMPARE",
            _ => out.reason = "SCANNER_FINDING_IDENTITIES_UNQUALIFIED",
        }
    }
    // Delta REVIEW is informational; absolute candidate findings still block.
    out.overall_decision = if out.candidate.decision == ScanDecision::Blocked
        || out.delta_decision == DeltaDecision::Blocked
    {
        DeltaDecision::Blocked
    } else if out.candidate.decision == ScanDecision::Unknown
        || out.delta_decision == DeltaDecision::Unknown
    {
        DeltaDecision::Unknown
    } else {
        DeltaDecision::Review
    };
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn trivy(vulns: Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "SchemaVersion":2,"ArtifactName":"same-image",
            "Results":[{"Target":"image-packages","Vulnerabilities":vulns}]
        }))
        .unwrap()
    }
    fn issue(id: &str, severity: &str) -> Value {
        serde_json::json!({"VulnerabilityID":id,"PkgName":"example","InstalledVersion":"1","Severity":severity})
    }
    #[test]
    fn clean_to_critical_is_new_absolute_and_delta_blocker() {
        let a = trivy(serde_json::json!([]));
        let b = trivy(serde_json::json!([issue("TEST-A", "CRITICAL")]));
        let r = compare_reports(&a, &b, ScannerFormat::TrivyJsonV2, "same-image");
        assert_eq!(r.delta_decision, DeltaDecision::Blocked);
        assert_eq!(r.overall_decision, DeltaDecision::Blocked);
        assert_eq!(r.new_occurrences, Some(1));
        assert!(!r.production_ready);
    }
    #[test]
    fn pre_existing_critical_stays_absolute_block_even_if_delta_is_review() {
        let a = trivy(serde_json::json!([issue("TEST-A", "CRITICAL")]));
        let b = a.clone();
        let r = compare_reports(&a, &b, ScannerFormat::TrivyJsonV2, "same-image");
        assert_eq!(r.new_occurrences, Some(0));
        assert_eq!(r.persistent_occurrences, Some(1));
        assert_eq!(r.delta_decision, DeltaDecision::Review);
        assert_eq!(r.overall_decision, DeltaDecision::Blocked);
    }
    #[test]
    fn resolved_issue_is_counted_but_never_approved() {
        let a = trivy(serde_json::json!([issue("TEST-A", "HIGH")]));
        let b = trivy(serde_json::json!([]));
        let r = compare_reports(&a, &b, ScannerFormat::TrivyJsonV2, "same-image");
        assert_eq!(r.resolved_occurrences, Some(1));
        assert_eq!(r.overall_decision, DeltaDecision::Review);
        assert!(!r.action_authorized);
    }
    #[test]
    fn severity_escalation_high_to_critical_is_a_new_blocker() {
        let a = trivy(serde_json::json!([issue("TEST-A", "HIGH")]));
        let b = trivy(serde_json::json!([issue("TEST-A", "CRITICAL")]));
        let r = compare_reports(&a, &b, ScannerFormat::TrivyJsonV2, "same-image");
        assert_eq!(r.severity_escalations, Some(1));
        assert_eq!(r.new_blocking_occurrences, Some(1));
        assert_eq!(r.delta_decision, DeltaDecision::Blocked);
    }
    #[test]
    fn different_trivy_result_targets_fail_closed() {
        let a = trivy(serde_json::json!([]));
        let b = serde_json::to_vec(&serde_json::json!({
            "SchemaVersion":2,"ArtifactName":"same-image",
            "Results":[{"Target":"another-scope","Vulnerabilities":[]}]
        }))
        .unwrap();
        let r = compare_reports(&a, &b, ScannerFormat::TrivyJsonV2, "same-image");
        assert_eq!(r.delta_decision, DeltaDecision::Unknown);
        assert_eq!(r.new_occurrences, None);
    }
    #[test]
    fn trivy_multi_scanner_same_target_comparison_does_not_collapse_scopes() {
        let baseline = serde_json::json!({
            "SchemaVersion":2,"ArtifactName":"same-image",
            "Results":[
                {"Target":"repo","Class":"lang-pkgs","Vulnerabilities":[]},
                {"Target":"repo","Class":"secret","Secrets":[]}
            ]
        });
        let candidate = serde_json::json!({
            "SchemaVersion":2,"ArtifactName":"same-image",
            "Results":[
                {"Target":"repo","Class":"lang-pkgs","Vulnerabilities":[]},
                {"Target":"repo","Class":"secret","Secrets":[{"RuleID":"SYNTHETIC-ID","Match":"DO_NOT_ECHO_THIS_SECRET"}]}
            ]
        });
        let r = compare_reports(
            &serde_json::to_vec(&baseline).unwrap(),
            &serde_json::to_vec(&candidate).unwrap(),
            ScannerFormat::TrivyJsonV2,
            "same-image",
        );
        assert_eq!(r.delta_decision, DeltaDecision::Blocked);
        assert_eq!(r.new_occurrences, Some(1));
        assert_eq!(r.new_sample[0].id, "SYNTHETIC-ID");
        assert!(
            !serde_json::to_string(&r)
                .unwrap()
                .contains("DO_NOT_ECHO_THIS_SECRET")
        );
    }
    #[test]
    fn changed_scanner_classes_and_coverage_are_unknown_even_with_new_secret() {
        let baseline = serde_json::json!({
            "SchemaVersion":2,"ArtifactName":"same-image",
            "Results":[{"Target":"repo","Class":"lang-pkgs","Vulnerabilities":[]}]});
        let candidate = serde_json::json!({
            "SchemaVersion":2,"ArtifactName":"same-image",
            "Results":[
                {"Target":"repo","Class":"lang-pkgs","Vulnerabilities":[]},
                {"Target":"repo","Class":"secret","Secrets":[{"RuleID":"SYNTHETIC-NEW"}]}
            ]
        });
        let r = compare_reports(
            &serde_json::to_vec(&baseline).unwrap(),
            &serde_json::to_vec(&candidate).unwrap(),
            ScannerFormat::TrivyJsonV2,
            "same-image",
        );
        assert_eq!(r.new_occurrences, None);
        assert_eq!(r.delta_decision, DeltaDecision::Unknown);
        assert_eq!(r.overall_decision, DeltaDecision::Blocked);
    }
    #[test]
    fn severity_low_to_high_is_a_new_blocking_escalation() {
        let a = trivy(serde_json::json!([issue("TEST-A", "LOW")]));
        let b = trivy(serde_json::json!([issue("TEST-A", "HIGH")]));
        let r = compare_reports(&a, &b, ScannerFormat::TrivyJsonV2, "same-image");
        assert_eq!(r.new_occurrences, Some(0));
        assert_eq!(r.severity_escalations, Some(1));
        assert_eq!(r.new_blocking_occurrences, Some(1));
        assert_eq!(r.delta_decision, DeltaDecision::Blocked);
    }
    #[test]
    fn medium_new_finding_is_reported_but_review_not_ready() {
        let a = trivy(serde_json::json!([]));
        let b = trivy(serde_json::json!([issue("TEST-M", "MEDIUM")]));
        let r = compare_reports(&a, &b, ScannerFormat::TrivyJsonV2, "same-image");
        assert_eq!(r.new_occurrences, Some(1));
        assert_eq!(r.new_blocking_occurrences, Some(0));
        assert_eq!(r.delta_decision, DeltaDecision::Review);
        assert!(!r.production_ready);
    }
    #[test]
    fn unqualified_osv_source_type_cannot_generate_zero_delta() {
        let a=br#"{"results":[{"source":{"path":"Cargo.lock"},"packages":[{"package":{"name":"a","version":"1","ecosystem":"crates.io"},"vulnerabilities":[]}]}]}"#;
        let r = compare_reports(a, a, ScannerFormat::OsvScannerJsonV2, "Cargo.lock");
        assert_eq!(r.new_occurrences, None);
        assert_eq!(r.delta_decision, DeltaDecision::Unknown);
    }
    #[test]
    fn invalid_candidate_finding_identity_does_not_create_false_zero() {
        let a = trivy(serde_json::json!([]));
        let b = trivy(
            serde_json::json!([{"VulnerabilityID":"","PkgName":"x","InstalledVersion":"1","Severity":"CRITICAL"}]),
        );
        let r = compare_reports(&a, &b, ScannerFormat::TrivyJsonV2, "same-image");
        assert_eq!(r.new_occurrences, None);
        assert_eq!(r.delta_decision, DeltaDecision::Unknown);
        assert_eq!(r.overall_decision, DeltaDecision::Blocked);
    }
    #[test]
    fn oversized_new_findings_show_bounded_samples_and_exact_count() {
        let a = trivy(serde_json::json!([]));
        let candidate = (0..31)
            .map(|i| issue(&format!("SYNTHETIC-{i}"), "CRITICAL"))
            .collect::<Vec<_>>();
        let b = trivy(serde_json::json!(candidate));
        let r = compare_reports(&a, &b, ScannerFormat::TrivyJsonV2, "same-image");
        assert_eq!(r.new_occurrences, Some(31));
        assert_eq!(r.new_blocking_occurrences, Some(31));
        assert_eq!(r.new_sample.len(), 20);
        assert!(r.findings_sample_truncated);
    }
    #[test]
    fn osv_all_packages_native_missing_vulnerability_fields_are_comparable() {
        let baseline=br#"{"results":[{"source":{"path":"Cargo.lock","type":"lockfile"},"packages":[{"package":{"name":"safe","version":"1","ecosystem":"crates.io"}},{"package":{"name":"bad","version":"1","ecosystem":"crates.io"},"vulnerabilities":[{"id":"RUSTSEC-TEST"}]}]}]}"#;
        let candidate=br#"{"results":[{"source":{"path":"Cargo.lock","type":"lockfile"},"packages":[{"package":{"name":"safe","version":"2","ecosystem":"crates.io"}},{"package":{"name":"bad","version":"1","ecosystem":"crates.io"},"vulnerabilities":[{"id":"RUSTSEC-TEST"}]}]}]}"#;
        let report = compare_reports(
            baseline,
            candidate,
            ScannerFormat::OsvScannerJsonV2,
            "Cargo.lock",
        );
        assert_eq!(report.new_occurrences, Some(0));
        assert_eq!(report.persistent_occurrences, Some(1));
        assert_eq!(report.delta_decision, DeltaDecision::Review);
        assert_eq!(report.overall_decision, DeltaDecision::Blocked);
    }
    #[test]
    fn osv_existing_advisory_is_not_falsely_approved() {
        let a=br#"{"results":[{"source":{"path":"Cargo.lock","type":"lockfile"},"packages":[{"package":{"name":"a","version":"1","ecosystem":"crates.io"},"vulnerabilities":[{"id":"OSV-FAKE"}]}]}]}"#;
        let b=br#"{"results":[{"source":{"path":"Cargo.lock","type":"lockfile"},"packages":[{"package":{"name":"a","version":"2","ecosystem":"crates.io"},"vulnerabilities":[{"id":"OSV-FAKE"}]}]}]}"#;
        let r = compare_reports(a, b, ScannerFormat::OsvScannerJsonV2, "Cargo.lock");
        assert_eq!(r.persistent_occurrences, Some(1));
        assert_eq!(r.delta_decision, DeltaDecision::Review);
        assert_eq!(r.overall_decision, DeltaDecision::Blocked);
    }
}
