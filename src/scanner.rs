//! Read-only, bounded native scanner JSON inspection.
//!
//! An existing Trivy or OSV-Scanner report is inspected, not executed.
//! JSON structure / counts prove neither execution nor coverage beyond the
//! explicit scan target; no "production ready" state exists.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScannerFormat {
    TrivyJsonV2,
    OsvScannerJsonV2,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanSpec {
    pub format: ScannerFormat,
    pub expected_subject: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanDecision {
    Blocked,
    Unknown,
    Review,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub format: ScannerFormat,
    pub decision: ScanDecision,
    pub reason: &'static str,
    pub expected_subject_matched: bool,
    pub reviewed_entries: usize,
    pub vulnerability_occurrences: usize,
    pub misconfiguration_occurrences: usize,
    pub high_or_critical_occurrences: usize,
    pub secret_occurrences: usize,
    pub unknown_severity_occurrences: usize,
    pub source_commit_attested_by_scanner: bool,
    pub scanner_execution_attested: bool,
    pub complete_scan_coverage_attested: bool,
    pub production_ready: bool,
}

impl ScanSummary {
    fn empty(format: ScannerFormat) -> Self {
        Self {
            format,
            decision: ScanDecision::Unknown,
            reason: "SCAN_JSON_MISSING_OR_UNSUPPORTED",
            expected_subject_matched: false,
            reviewed_entries: 0,
            vulnerability_occurrences: 0,
            misconfiguration_occurrences: 0,
            high_or_critical_occurrences: 0,
            secret_occurrences: 0,
            unknown_severity_occurrences: 0,
            source_commit_attested_by_scanner: false,
            scanner_execution_attested: false,
            complete_scan_coverage_attested: false,
            production_ready: false,
        }
    }
}

pub fn valid_subject(subject: &str) -> bool {
    !subject.is_empty() && subject.len() <= 512 && !subject.chars().any(char::is_control)
}

fn array_at<'a>(value: &'a Value, name: &str) -> Option<&'a Vec<Value>> {
    value.get(name).and_then(Value::as_array)
}

fn nonempty_string(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|v| !v.trim().is_empty())
}

fn severity(value: &Value, report: &mut ScanSummary) -> bool {
    match value.get("Severity").and_then(Value::as_str) {
        Some("HIGH" | "CRITICAL") => {
            report.high_or_critical_occurrences += 1;
            true
        }
        Some("MEDIUM" | "LOW") => true,
        Some("UNKNOWN") | None => {
            report.unknown_severity_occurrences += 1;
            false
        }
        _ => {
            report.unknown_severity_occurrences += 1;
            false
        }
    }
}

fn trivy(value: &Value, subject: &str, report: &mut ScanSummary) {
    if value.get("SchemaVersion").and_then(Value::as_u64) != Some(2) {
        report.reason = "TRIVY_SCHEMA_VERSION_NOT_SUPPORTED";
        return;
    }
    if value.get("ArtifactName").and_then(Value::as_str) != Some(subject) {
        report.decision = ScanDecision::Blocked;
        report.reason = "SCANNER_TARGET_MISMATCH";
        return;
    }
    report.expected_subject_matched = true;
    let Some(results) = array_at(value, "Results") else {
        report.reason = "TRIVY_RESULTS_NOT_PRESENT";
        return;
    };
    if results.is_empty() {
        report.reason = "TRIVY_RESULTS_EMPTY_NO_COVERAGE_PROOF";
        return;
    }
    // Only a populated vulnerability-analysis array establishes narrow,
    // structural evidence that *some* package target was assessed. An empty
    // JSON results list must never be treated as an all-clear.
    let mut observed_vuln_array = false;
    let mut malformed = false;
    for result in results.iter().take(10000) {
        if !nonempty_string(result, "Target") {
            malformed = true;
            continue;
        }
        report.reviewed_entries += 1;
        if let Some(vulns) = array_at(result, "Vulnerabilities") {
            observed_vuln_array = true;
            for vuln in vulns {
                report.vulnerability_occurrences += 1;
                if !nonempty_string(vuln, "VulnerabilityID")
                    || !nonempty_string(vuln, "PkgName")
                    || !nonempty_string(vuln, "InstalledVersion")
                {
                    malformed = true;
                }
                if !severity(vuln, report) {
                    malformed = true;
                }
            }
        } else if result.get("Vulnerabilities").is_some()
            && !result.get("Vulnerabilities").is_some_and(Value::is_null)
        {
            malformed = true;
        }
        for key in ["Secrets", "Misconfigurations"] {
            if let Some(items) = array_at(result, key) {
                for item in items {
                    if key == "Secrets" {
                        report.secret_occurrences += 1;
                    } else {
                        report.misconfiguration_occurrences += 1;
                        if !severity(item, report) {
                            malformed = true;
                        }
                    }
                }
            } else if result.get(key).is_some() && !result.get(key).is_some_and(Value::is_null) {
                malformed = true;
            }
        }
    }
    if results.len() > 10000 {
        malformed = true;
    }
    if report.high_or_critical_occurrences > 0 || report.secret_occurrences > 0 {
        report.decision = ScanDecision::Blocked;
        report.reason = "TRIVY_HIGH_CRITICAL_OR_SECRET_FINDING";
    } else if malformed {
        report.reason = "TRIVY_UNKNOWN_OR_MALFORMED_FINDING";
    } else if !observed_vuln_array {
        report.reason = "TRIVY_VULNERABILITY_SCAN_COVERAGE_NOT_ESTABLISHED";
    } else {
        report.decision = ScanDecision::Review;
        report.reason = "TRIVY_REPORT_PARSED_REVIEW_ONLY";
    }
}

fn osv(value: &Value, subject: &str, report: &mut ScanSummary) {
    let Some(results) = array_at(value, "results") else {
        report.reason = "OSV_RESULTS_NOT_PRESENT";
        return;
    };
    if results.is_empty() {
        report.reason = "OSV_EMPTY_RESULTS_NO_PACKAGE_COVERAGE_PROOF";
        return;
    }
    let mut malformed = false;
    let mut mismatched = false;
    let mut parsed_packages = 0usize;
    for result in results.iter().take(10000) {
        let path = result
            .get("source")
            .and_then(|s| s.get("path"))
            .and_then(Value::as_str);
        match path {
            Some(p) if p == subject => {}
            Some(_) => mismatched = true,
            None => malformed = true,
        }
        let Some(packages) = array_at(result, "packages") else {
            malformed = true;
            continue;
        };
        report.reviewed_entries += 1;
        for package in packages {
            let meta = package.get("package");
            if !meta.is_some_and(|p| nonempty_string(p, "name") && nonempty_string(p, "version")) {
                malformed = true;
            }
            let Some(vulns) = array_at(package, "vulnerabilities") else {
                malformed = true;
                continue;
            };
            parsed_packages += 1;
            for vuln in vulns {
                report.vulnerability_occurrences += 1;
                if !nonempty_string(vuln, "id") {
                    malformed = true;
                }
            }
        }
    }
    if results.len() > 10000 {
        malformed = true;
    }
    if mismatched {
        report.decision = ScanDecision::Blocked;
        report.reason = "SCANNER_TARGET_MISMATCH";
        return;
    }
    if report.vulnerability_occurrences > 0 {
        // A confirmed advisory takes precedence over any missing coverage
        // elsewhere in the file. Unknown is not allowed to conceal a BLOCK.
        report.decision = ScanDecision::Blocked;
        report.reason = "OSV_VULNERABILITIES_REPORTED";
    } else if malformed {
        report.reason = "OSV_MALFORMED_PACKAGE_OR_SOURCE";
    } else if parsed_packages > 0 {
        report.decision = ScanDecision::Review;
        report.reason = "OSV_PACKAGES_WITH_NO_REPORTED_VULNERABILITIES";
    } else {
        report.reason = "OSV_NO_SCANNED_PACKAGES_PROVEN";
    }
}

/// Pure evaluation of a supplied local scanner JSON file. Input bytes are
/// expected to have been read and hashed exactly once by the caller.
pub fn inspect_scanner(bytes: &[u8], format: ScannerFormat, subject: &str) -> ScanSummary {
    let mut report = ScanSummary::empty(format);
    if !valid_subject(subject) || bytes.is_empty() || bytes.len() > 8 * 1024 * 1024 {
        report.reason = "SCAN_SUBJECT_OR_BYTES_OUT_OF_BOUNDS";
        return report;
    }
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        report.reason = "SCANNER_JSON_INVALID";
        return report;
    };
    match format {
        ScannerFormat::TrivyJsonV2 => trivy(&value, subject, &mut report),
        ScannerFormat::OsvScannerJsonV2 => osv(&value, subject, &mut report),
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    fn trivy_json(vulnerabilities: Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "SchemaVersion":2,"ArtifactName":"repo-image@sha256:synthetic",
            "Results":[{"Target":"app","Class":"lang-pkgs","Vulnerabilities":vulnerabilities}]
        }))
        .unwrap()
    }
    const SUBJECT: &str = "repo-image@sha256:synthetic";
    #[test]
    fn high_severity_is_blocked_regardless_of_caller_status() {
        let data = trivy_json(
            serde_json::json!([{"VulnerabilityID":"TEST-1","PkgName":"a","InstalledVersion":"1","Severity":"HIGH"}]),
        );
        let r = inspect_scanner(&data, ScannerFormat::TrivyJsonV2, SUBJECT);
        assert_eq!(r.decision, ScanDecision::Blocked);
        assert_eq!(r.high_or_critical_occurrences, 1);
        assert!(!r.production_ready);
    }
    #[test]
    fn clean_nonempty_target_is_only_review() {
        let r = inspect_scanner(
            &trivy_json(serde_json::json!([])),
            ScannerFormat::TrivyJsonV2,
            SUBJECT,
        );
        assert_eq!(r.decision, ScanDecision::Review);
        assert!(!r.scanner_execution_attested);
        assert!(!r.complete_scan_coverage_attested);
    }
    #[test]
    fn empty_results_and_unrecognized_schema_are_unknown() {
        for raw in [
            r#"{"SchemaVersion":2,"ArtifactName":"repo-image@sha256:synthetic","Results":[]}"#,
            r#"{"SchemaVersion":9,"ArtifactName":"repo-image@sha256:synthetic","Results":[]}"#,
        ] {
            assert_eq!(
                inspect_scanner(raw.as_bytes(), ScannerFormat::TrivyJsonV2, SUBJECT).decision,
                ScanDecision::Unknown
            );
        }
    }
    #[test]
    fn wrong_subject_blocks_even_without_findings() {
        let r = inspect_scanner(
            &trivy_json(serde_json::json!([])),
            ScannerFormat::TrivyJsonV2,
            "other",
        );
        assert_eq!(r.decision, ScanDecision::Blocked);
    }
    #[test]
    fn secrets_block_and_unknown_severity_is_unknown() {
        let raw=br#"{"SchemaVersion":2,"ArtifactName":"repo-image@sha256:synthetic","Results":[{"Target":"a","Vulnerabilities":[],"Secrets":[{"RuleID":"test"}]}]}"#;
        let report = inspect_scanner(raw, ScannerFormat::TrivyJsonV2, SUBJECT);
        assert_eq!(report.decision, ScanDecision::Blocked);
        assert_eq!(report.secret_occurrences, 1);
        let raw = trivy_json(
            serde_json::json!([{"VulnerabilityID":"x","PkgName":"x","InstalledVersion":"1","Severity":"OTHER"}]),
        );
        assert_eq!(
            inspect_scanner(&raw, ScannerFormat::TrivyJsonV2, SUBJECT).decision,
            ScanDecision::Unknown
        );
    }
    #[test]
    fn critical_misconfiguration_is_not_miscounted_as_a_vulnerability() {
        let raw=br#"{"SchemaVersion":2,"ArtifactName":"repo-image@sha256:synthetic","Results":[{"Target":"Dockerfile","Vulnerabilities":[],"Misconfigurations":[{"ID":"SYNTHETIC-MISCONFIG","Severity":"CRITICAL"}]}]}"#;
        let r = inspect_scanner(raw, ScannerFormat::TrivyJsonV2, SUBJECT);
        assert_eq!(r.decision, ScanDecision::Blocked);
        assert_eq!(r.misconfiguration_occurrences, 1);
        assert_eq!(r.vulnerability_occurrences, 0);
        assert_eq!(r.high_or_critical_occurrences, 1);
    }
    #[test]
    fn osv_reports_vulnerabilities_without_severity_inference() {
        let raw=br#"{"results":[{"source":{"path":"Cargo.lock","type":"lockfile"},"packages":[{"package":{"name":"a","version":"1"},"vulnerabilities":[{"id":"TEST-ADV"}]}]}]}"#;
        let report = inspect_scanner(raw, ScannerFormat::OsvScannerJsonV2, "Cargo.lock");
        assert_eq!(report.decision, ScanDecision::Blocked);
        assert_eq!(report.vulnerability_occurrences, 1);
    }
    #[test]
    fn osv_empty_and_no_packages_are_unknown() {
        for raw in [
            r#"{"results":[]}"#,
            r#"{"results":[{"source":{"path":"Cargo.lock"},"packages":[]}]}"#,
        ] {
            assert_eq!(
                inspect_scanner(
                    raw.as_bytes(),
                    ScannerFormat::OsvScannerJsonV2,
                    "Cargo.lock"
                )
                .decision,
                ScanDecision::Unknown
            );
        }
    }
    #[test]
    fn osv_confirmed_finding_takes_priority_over_an_unscanned_package() {
        let raw=br#"{"results":[{"source":{"path":"Cargo.lock"},"packages":[{"package":{"name":"a","version":"1"},"vulnerabilities":[{"id":"TEST"}]},{"package":{"name":"b","version":"1"}}]}]}"#;
        let r = inspect_scanner(raw, ScannerFormat::OsvScannerJsonV2, "Cargo.lock");
        assert_eq!(r.decision, ScanDecision::Blocked);
        assert_eq!(r.vulnerability_occurrences, 1);
    }
    #[test]
    fn osv_clean_package_is_review_only() {
        let raw=br#"{"results":[{"source":{"path":"Cargo.lock"},"packages":[{"package":{"name":"a","version":"1"},"vulnerabilities":[]}]}]}"#;
        let r = inspect_scanner(raw, ScannerFormat::OsvScannerJsonV2, "Cargo.lock");
        assert_eq!(r.decision, ScanDecision::Review);
    }
    #[test]
    fn malformed_json_and_wrong_subject_never_review() {
        assert_eq!(
            inspect_scanner(br#"{oops"#, ScannerFormat::OsvScannerJsonV2, "Cargo.lock").decision,
            ScanDecision::Unknown
        );
        let raw=br#"{"results":[{"source":{"path":"not-Cargo.lock"},"packages":[{"package":{"name":"a","version":"1"},"vulnerabilities":[]}]}]}"#;
        assert_eq!(
            inspect_scanner(raw, ScannerFormat::OsvScannerJsonV2, "Cargo.lock").decision,
            ScanDecision::Blocked
        );
    }
}
