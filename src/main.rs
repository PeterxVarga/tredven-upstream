use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use tredven_upstream::{
    Decision, PreflightInput, PreflightReport, contract::inspect_open_seo_0049,
    git_source::inspect_local_git, inspect, to_markdown,
};

const MAX_INPUT_BYTES: u64 = 1024 * 1024;

fn usage() -> &'static str {
    "Tredven Upstream — local read-only upgrade evidence\n\
     Usage: tredven-upstream inspect --input FILE|--stdin [--format json|markdown]\n\
     Usage: tredven-upstream inspect-git --repo DIR --project ID --from TAG --to TAG [--format json|markdown]\n\
     Usage: tredven-upstream inspect-contract --repo DIR --project open-seo --profile open-seo-v0.1.31-stripe-projects-0049 [--schema-snapshot FILE] [--format json|markdown]\n\
     Usage: tredven-upstream inspect-plan --manifest FILE [--format json|markdown]\n\
     Usage: tredven-upstream inspect-scan --input FILE --scanner trivy-json-v2|osv-scanner-json-v2 --subject TARGET [--format json|markdown]\n\
     Usage: tredven-upstream inspect-upgrade --repo DIR --project ID --from TAG --to TAG --scanner trivy-json-v2|osv-scanner-json-v2 --scan-report FILE --subject TARGET --scan-commit SHA [--format json|markdown]\n\
     Usage: tredven-upstream inspect-delta --baseline FILE --candidate FILE --scanner trivy-json-v2|osv-scanner-json-v2 --subject TARGET [--format json|markdown]\n\
     Usage: tredven-upstream inspect-upgrade-delta --repo DIR --project ID --from TAG --to TAG --baseline FILE --candidate FILE --scanner trivy-json-v2|osv-scanner-json-v2 --subject TARGET --baseline-commit SHA --candidate-commit SHA [--format json|markdown]\n\
     Usage: tredven-upstream review-upgrade --config FILE [--format json|markdown] [--evidence-dir NEW_DIRECTORY]\n\
     Usage: tredven-upstream verify-attestation --artifact FILE --repo OWNER/REPO --repo-id NUM --signer-workflow OWNER/REPO/.github/workflows/NAME.yml --source-ref refs/tags/TAG --source-commit SHA --bundle FILE --trusted-root FILE [--predicate-type URL] [--format json|markdown]\n\
     Shortcut: tredven-upstream verify-attestation --artifact FILE --policy POLICY.json [--format json|markdown]\n\
     Usage: tredven-upstream inspect-attested-scan --artifact REPORT.json --scanner trivy-json-v2|osv-scanner-json-v2 --subject TARGET --repo OWNER/REPO --repo-id NUM --signer-workflow OWNER/REPO/.github/workflows/NAME.yml --source-ref refs/tags/TAG --source-commit SHA --bundle FILE --trusted-root FILE [--format json|markdown]\n\
     Alternative: same verify-attestation arguments with --online instead of --bundle/--trusted-root (explicitly enables GitHub API lookups).\n\
     Git inspection is local only, never a remote release or production attestation.\n\
     No Docker, provider writes, mutations or deploy permissions. Only attestation commands with --online request public GitHub API lookups.\n"
}

fn fail(message: &str) -> ExitCode {
    eprintln!("ERROR: {message}");
    ExitCode::from(1)
}

fn emit(report: &PreflightReport, format: &str) -> Result<u8, String> {
    if !["json", "markdown"].contains(&format) {
        return Err("UNSUPPORTED_FORMAT".into());
    }
    let mut stdout = io::stdout().lock();
    if format == "json" {
        serde_json::to_writer_pretty(&mut stdout, report).map_err(|_| "JSON_OUTPUT_FAILED")?;
        writeln!(&mut stdout).map_err(|_| "STDOUT_WRITE_FAILED")?;
    } else {
        write!(&mut stdout, "{}", to_markdown(report)).map_err(|_| "STDOUT_WRITE_FAILED")?;
    }
    Ok(if report.decision == Decision::Blocked {
        2
    } else {
        0
    })
}

fn run_git(mut args: impl Iterator<Item = String>) -> Result<u8, String> {
    let (mut repo, mut project, mut from, mut to) = (None, None, None, None);
    let mut format = "json".to_owned();
    while let Some(arg) = args.next() {
        let value = match arg.as_str() {
            "--help" | "-h" => {
                print!("{}", usage());
                return Ok(0);
            }
            "--repo" | "--project" | "--from" | "--to" | "--format" => {
                args.next().ok_or("MISSING_GIT_ARGUMENT_VALUE")?
            }
            _ => return Err("UNRECOGNIZED_GIT_ARGUMENT".into()),
        };
        let target = match arg.as_str() {
            "--repo" => &mut repo,
            "--project" => &mut project,
            "--from" => &mut from,
            "--to" => &mut to,
            _ => {
                if format != "json" {
                    return Err("FORMAT_SPECIFIED_MORE_THAN_ONCE".into());
                }
                format = value;
                continue;
            }
        };
        if target.replace(value).is_some() {
            return Err("GIT_ARGUMENT_SPECIFIED_MORE_THAN_ONCE".into());
        }
    }
    let repo = repo.ok_or("MISSING_GIT_REPO")?;
    let project = project.ok_or("MISSING_GIT_PROJECT")?;
    let from = from.ok_or("MISSING_GIT_FROM_TAG")?;
    let to = to.ok_or("MISSING_GIT_TO_TAG")?;
    let report = inspect_local_git(Path::new(&repo), &project, &from, &to)?;
    emit(&report, &format)
}

fn run_contract(mut args: impl Iterator<Item = String>) -> Result<u8, String> {
    let (mut repo, mut project, mut profile, mut schema) = (None, None, None, None);
    let mut format = "json".to_owned();
    while let Some(arg) = args.next() {
        let value = match arg.as_str() {
            "--help" | "-h" => {
                print!("{}", usage());
                return Ok(0);
            }
            "--repo" | "--project" | "--profile" | "--schema-snapshot" | "--format" => {
                args.next().ok_or("MISSING_CONTRACT_ARGUMENT_VALUE")?
            }
            _ => return Err("UNRECOGNIZED_CONTRACT_ARGUMENT".into()),
        };
        let slot = match arg.as_str() {
            "--repo" => &mut repo,
            "--project" => &mut project,
            "--profile" => &mut profile,
            "--schema-snapshot" => &mut schema,
            "--format" => {
                format = value;
                continue;
            }
            _ => unreachable!(),
        };
        if slot.replace(value).is_some() {
            return Err("CONTRACT_ARGUMENT_SPECIFIED_MORE_THAN_ONCE".into());
        }
    }
    let repo = repo.ok_or("MISSING_CONTRACT_GIT_REPO")?;
    let project = project.ok_or("MISSING_CONTRACT_PROJECT")?;
    let profile = profile.ok_or("MISSING_CONTRACT_PROFILE")?;
    let report = inspect_open_seo_0049(
        Path::new(&repo),
        &project,
        &profile,
        schema.as_deref().map(Path::new),
    )?;
    emit(&report, &format)
}

fn emit_watch_report(report: &tredven_upstream::plan::Report, format: &str) -> Result<u8, String> {
    let mut stdout = io::stdout().lock();
    if format == "json" {
        serde_json::to_writer_pretty(&mut stdout, report).map_err(|_| "PLAN_JSON_OUTPUT_FAILED")?;
        writeln!(&mut stdout).map_err(|_| "STDOUT_WRITE_FAILED")?;
    } else {
        write!(&mut stdout, "{}", tredven_upstream::plan::markdown(report))
            .map_err(|_| "PLAN_MARKDOWN_OUTPUT_FAILED")?;
    }
    Ok(if report.total_blocked > 0 {
        2
    } else if report.total_unknown > 0 || report.total_watched == 0 {
        3
    } else {
        0
    })
}

fn run_plan(mut args: impl Iterator<Item = String>) -> Result<u8, String> {
    let mut manifest = None;
    let mut format = "json".to_owned();
    let mut format_seen = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--manifest" => {
                if manifest.is_some() {
                    return Err("DUPLICATE_PLAN_MANIFEST".into());
                }
                manifest = Some(args.next().ok_or("MISSING_PLAN_MANIFEST_VALUE")?);
            }
            "--format" => {
                if format_seen {
                    return Err("DUPLICATE_PLAN_FORMAT".into());
                }
                format_seen = true;
                format = args.next().ok_or("MISSING_PLAN_FORMAT_VALUE")?;
            }
            "--help" | "-h" => {
                print!("{}", usage());
                return Ok(0);
            }
            _ => return Err("UNRECOGNIZED_PLAN_ARGUMENT".into()),
        }
    }
    if format != "json" && format != "markdown" {
        return Err("UNSUPPORTED_FORMAT".into());
    }
    let path = manifest.ok_or("MISSING_PLAN_MANIFEST")?;
    let path = Path::new(&path);
    let meta = fs::symlink_metadata(path).map_err(|_| "PLAN_MANIFEST_UNAVAILABLE")?;
    if !meta.file_type().is_file() || meta.len() > 512 * 1024 {
        return Err("PLAN_MANIFEST_NOT_BOUNDED_REGULAR_FILE".into());
    }
    let raw = fs::read(path).map_err(|_| "PLAN_MANIFEST_READ_FAILED")?;
    if raw.len() > 512 * 1024 {
        return Err("PLAN_MANIFEST_TOO_LARGE".into());
    }
    let input: tredven_upstream::plan::WatchPlan =
        serde_json::from_slice(&raw).map_err(|_| "INVALID_PLAN_JSON")?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let report = tredven_upstream::plan::inspect_plan(input, parent)?;
    emit_watch_report(&report, &format)
}

fn run_scan(mut args: impl Iterator<Item = String>) -> Result<u8, String> {
    use tredven_upstream::scanner::{ScanDecision, ScannerFormat, inspect_scanner, valid_subject};
    let (mut input, mut scanner, mut subject) = (None, None, None);
    let mut format = "json".to_owned();
    let mut format_seen = false;
    while let Some(key) = args.next() {
        if key == "--help" || key == "-h" {
            print!("{}", usage());
            return Ok(0);
        }
        let value = args.next().ok_or("MISSING_SCANNER_ARG_VALUE")?;
        let place = match key.as_str() {
            "--input" => &mut input,
            "--scanner" => &mut scanner,
            "--subject" => &mut subject,
            "--format" => {
                if format_seen {
                    return Err("DUPLICATE_SCANNER_FORMAT".into());
                }
                format_seen = true;
                format = value;
                continue;
            }
            _ => return Err("UNKNOWN_SCANNER_ARG".into()),
        };
        if place.replace(value).is_some() {
            return Err("DUPLICATE_SCANNER_ARG".into());
        }
    }
    if !["json", "markdown"].contains(&format.as_str()) {
        return Err("UNSUPPORTED_FORMAT".into());
    }
    let path = input.ok_or("MISSING_SCANNER_INPUT")?;
    let path = Path::new(&path);
    let meta = fs::symlink_metadata(path).map_err(|_| "SCANNER_REPORT_NOT_FOUND")?;
    if !meta.file_type().is_file() || meta.len() > 8 * 1024 * 1024 {
        return Err("SCANNER_REPORT_MUST_BE_BOUNDED_REGULAR_FILE".into());
    }
    let raw = fs::read(path).map_err(|_| "SCANNER_REPORT_READ_FAILED")?;
    let scanner = match scanner.ok_or("MISSING_SCANNER_FORMAT")?.as_str() {
        "trivy-json-v2" => ScannerFormat::TrivyJsonV2,
        "osv-scanner-json-v2" => ScannerFormat::OsvScannerJsonV2,
        _ => return Err("UNSUPPORTED_SCANNER_FORMAT".into()),
    };
    let subject = subject.ok_or("MISSING_SCANNER_SUBJECT")?;
    if !valid_subject(&subject) {
        return Err("INVALID_SCANNER_SUBJECT".into());
    }
    let report = inspect_scanner(&raw, scanner, &subject);
    let mut out = io::stdout().lock();
    if format == "json" {
        serde_json::to_writer_pretty(&mut out, &report)
            .map_err(|_| "SCANNER_JSON_OUTPUT_FAILED")?;
        writeln!(&mut out).map_err(|_| "STDOUT_WRITE_FAILED")?;
    } else {
        writeln!(&mut out,"# Local scanner report (not an approval)\n\nFormat: {:?}\nDecision: {:?}\nReason: {}\nVulnerability occurrences: {}, misconfigurations: {}, high/critical: {}, secrets: {}\nSource commit and scanner execution NOT ATTESTED.\n",report.format,report.decision,report.reason,report.vulnerability_occurrences,report.misconfiguration_occurrences,report.high_or_critical_occurrences,report.secret_occurrences)
            .map_err(|_|"SCANNER_MARKDOWN_OUTPUT_FAILED")?;
    }
    Ok(match report.decision {
        ScanDecision::Review => 0,
        ScanDecision::Blocked => 2,
        ScanDecision::Unknown => 3,
    })
}

fn run_upgrade(mut args: impl Iterator<Item = String>) -> Result<u8, String> {
    use sha2::{Digest, Sha256};
    use tredven_upstream::CheckStatus;
    use tredven_upstream::plan::{ArtifactPin, Evidence, Target, WatchPlan};
    use tredven_upstream::scanner::{ScanSpec, ScannerFormat, valid_subject};
    let (
        mut repo,
        mut project,
        mut from,
        mut to,
        mut scanner,
        mut scan_report,
        mut subject,
        mut scan_commit,
    ) = (None, None, None, None, None, None, None, None);
    let mut format = "json".to_owned();
    let mut fmt_seen = false;
    while let Some(arg) = args.next() {
        if ["--help", "-h"].contains(&arg.as_str()) {
            print!("{}", usage());
            return Ok(0);
        }
        let value = args.next().ok_or("MISSING_UPGRADE_ARG_VALUE")?;
        let place = match arg.as_str() {
            "--repo" => &mut repo,
            "--project" => &mut project,
            "--from" => &mut from,
            "--to" => &mut to,
            "--scanner" => &mut scanner,
            "--scan-report" => &mut scan_report,
            "--subject" => &mut subject,
            "--scan-commit" => &mut scan_commit,
            "--format" => {
                if fmt_seen {
                    return Err("DUPLICATE_UPGRADE_FORMAT".into());
                }
                fmt_seen = true;
                format = value;
                continue;
            }
            _ => return Err("UNKNOWN_UPGRADE_ARGUMENT".into()),
        };
        if place.replace(value).is_some() {
            return Err("DUPLICATE_UPGRADE_ARGUMENT".into());
        }
    }
    if !["json", "markdown"].contains(&format.as_str()) {
        return Err("UNSUPPORTED_FORMAT".into());
    }
    let repo = repo.ok_or("MISSING_UPGRADE_REPO")?;
    let project = project.ok_or("MISSING_UPGRADE_PROJECT")?;
    let from = from.ok_or("MISSING_UPGRADE_FROM_TAG")?;
    let to = to.ok_or("MISSING_UPGRADE_TO_TAG")?;
    let subject = subject.ok_or("MISSING_UPGRADE_SCAN_SUBJECT")?;
    if !valid_subject(&subject) {
        return Err("INVALID_SCANNER_SUBJECT".into());
    }
    let scanner = match scanner.ok_or("MISSING_UPGRADE_SCANNER")?.as_str() {
        "trivy-json-v2" => ScannerFormat::TrivyJsonV2,
        "osv-scanner-json-v2" => ScannerFormat::OsvScannerJsonV2,
        _ => return Err("UNSUPPORTED_SCANNER_FORMAT".into()),
    };
    let path = scan_report.ok_or("MISSING_UPGRADE_SCANNER_FILE")?;
    let file = Path::new(&path);
    let meta = fs::symlink_metadata(file).map_err(|_| "SCANNER_REPORT_NOT_FOUND")?;
    if !meta.file_type().is_file() || meta.len() > 8 * 1024 * 1024 {
        return Err("SCANNER_REPORT_MUST_BE_BOUNDED_REGULAR_FILE".into());
    }
    let bytes = fs::read(file).map_err(|_| "SCANNER_REPORT_READ_FAILED")?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("SCANNER_REPORT_TOO_LARGE".into());
    }
    let pin = format!("{:x}", Sha256::digest(&bytes));
    let tool = match scanner {
        ScannerFormat::TrivyJsonV2 => "trivy",
        ScannerFormat::OsvScannerJsonV2 => "osv-scanner",
    };
    let request = WatchPlan {
        schema: tredven_upstream::plan::SCHEMA.into(),
        targets: vec![Target {
            id: project,
            group: "one-shot".into(),
            enabled: true,
            repo,
            from_tag: from,
            to_tag: to,
            required_evidence: vec![Evidence {
                id: "native-security-report".into(),
                source_tool: tool.into(),
                status: CheckStatus::Unknown,
                // This is a caller declaration. The scanner JSON cannot
                // independently prove it ran against this specific source SHA.
                candidate_commit: Some(scan_commit.ok_or("MISSING_UPGRADE_SCAN_COMMIT")?),
                artifact: Some(ArtifactPin { path, sha256: pin }),
                scan: Some(ScanSpec {
                    format: scanner,
                    expected_subject: subject,
                }),
            }],
        }],
    };
    let report = tredven_upstream::plan::inspect_plan(request, Path::new("."))?;
    emit_watch_report(&report, &format)
}

fn bounded_scan_file(path: &str) -> Result<Vec<u8>, String> {
    let path = Path::new(path);
    let metadata = fs::symlink_metadata(path).map_err(|_| "SCANNER_REPORT_NOT_FOUND")?;
    if !metadata.file_type().is_file() || metadata.len() > 8 * 1024 * 1024 {
        return Err("SCANNER_REPORT_MUST_BE_BOUNDED_REGULAR_FILE".into());
    }
    let bytes = fs::read(path).map_err(|_| "SCANNER_REPORT_READ_FAILED")?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("SCANNER_REPORT_TOO_LARGE".into());
    }
    Ok(bytes)
}

fn delta_exit(decision: tredven_upstream::delta::DeltaDecision) -> u8 {
    use tredven_upstream::delta::DeltaDecision;
    match decision {
        DeltaDecision::Blocked => 2,
        DeltaDecision::Unknown => 3,
        DeltaDecision::Review => 0,
    }
}

fn run_delta(mut args: impl Iterator<Item = String>, with_git: bool) -> Result<u8, String> {
    use tredven_upstream::delta::{DeltaDecision, compare_reports};
    use tredven_upstream::scanner::{ScannerFormat, valid_subject};
    let (mut baseline, mut candidate, mut scanner, mut subject) = (None, None, None, None);
    let (mut repo, mut project, mut from, mut to, mut baseline_commit, mut candidate_commit) =
        (None, None, None, None, None, None);
    let mut format = "json".to_owned();
    let mut format_seen = false;
    while let Some(key) = args.next() {
        if ["--help", "-h"].contains(&key.as_str()) {
            print!("{}", usage());
            return Ok(0);
        }
        let value = args.next().ok_or("MISSING_DELTA_OPTION_VALUE")?;
        let place = match key.as_str() {
            "--baseline" => &mut baseline,
            "--candidate" => &mut candidate,
            "--scanner" => &mut scanner,
            "--subject" => &mut subject,
            "--repo" if with_git => &mut repo,
            "--project" if with_git => &mut project,
            "--from" if with_git => &mut from,
            "--to" if with_git => &mut to,
            "--baseline-commit" if with_git => &mut baseline_commit,
            "--candidate-commit" if with_git => &mut candidate_commit,
            "--format" => {
                if format_seen {
                    return Err("DUPLICATE_DELTA_FORMAT".into());
                }
                format_seen = true;
                format = value;
                continue;
            }
            _ => return Err("UNRECOGNIZED_DELTA_OPTION".into()),
        };
        if place.replace(value).is_some() {
            return Err("DUPLICATE_DELTA_OPTION".into());
        }
    }
    if !["json", "markdown"].contains(&format.as_str()) {
        return Err("UNSUPPORTED_FORMAT".into());
    }
    let subject = subject.ok_or("MISSING_DELTA_SUBJECT")?;
    if !valid_subject(&subject) {
        return Err("INVALID_DELTA_SUBJECT".into());
    }
    let scanner = match scanner.ok_or("MISSING_DELTA_SCANNER")?.as_str() {
        "trivy-json-v2" => ScannerFormat::TrivyJsonV2,
        "osv-scanner-json-v2" => ScannerFormat::OsvScannerJsonV2,
        _ => return Err("UNSUPPORTED_SCANNER_FORMAT".into()),
    };
    let before = bounded_scan_file(&baseline.ok_or("MISSING_DELTA_BASELINE_FILE")?)?;
    let after = bounded_scan_file(&candidate.ok_or("MISSING_DELTA_CANDIDATE_FILE")?)?;
    let delta = compare_reports(&before, &after, scanner, &subject);
    let mut stdout = io::stdout().lock();
    if !with_git {
        if format == "json" {
            serde_json::to_writer_pretty(&mut stdout, &delta)
                .map_err(|_| "DELTA_JSON_WRITE_FAILED")?;
            writeln!(&mut stdout).map_err(|_| "DELTA_STDOUT_WRITE_FAILED")?;
        } else {
            write!(&mut stdout, "{}", delta.to_markdown())
                .map_err(|_| "DELTA_MARKDOWN_WRITE_FAILED")?;
        }
        return Ok(delta_exit(delta.overall_decision));
    }
    use serde::Serialize;
    use tredven_upstream::Decision;
    #[derive(Serialize)]
    struct UpgradeDeltaEnvelope {
        schema: &'static str,
        source: tredven_upstream::PreflightReport,
        scanner_delta: tredven_upstream::delta::ScanDeltaReport,
        baseline_commit_binding: bool,
        candidate_commit_binding: bool,
        decision: DeltaDecision,
        reason: &'static str,
        scanner_execution_attested: bool,
        production_ready: bool,
        action_authorized: bool,
        performed_remote_queries: bool,
        performed_mutations: bool,
    }
    let source = inspect_local_git(
        Path::new(&repo.ok_or("MISSING_DELTA_GIT_REPO")?),
        &project.ok_or("MISSING_DELTA_PROJECT")?,
        &from.ok_or("MISSING_DELTA_FROM_TAG")?,
        &to.ok_or("MISSING_DELTA_TO_TAG")?,
    )?;
    let bound_base = baseline_commit.ok_or("MISSING_DELTA_BASELINE_COMMIT")?;
    let bound_cand = candidate_commit.ok_or("MISSING_DELTA_CANDIDATE_COMMIT")?;
    let format_sha = |s: &str| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit());
    if !format_sha(&bound_base) || !format_sha(&bound_cand) {
        return Err("INVALID_DELTA_COMMIT_PIN".into());
    }
    let baseline_bound = source
        .baseline_commit
        .as_ref()
        .is_some_and(|x| x.eq_ignore_ascii_case(&bound_base));
    let candidate_bound = source
        .candidate_commit
        .as_ref()
        .is_some_and(|x| x.eq_ignore_ascii_case(&bound_cand));
    let decision = if !baseline_bound || !candidate_bound || source.decision == Decision::Blocked {
        DeltaDecision::Blocked
    } else if source.decision == Decision::Unknown
        || delta.overall_decision == DeltaDecision::Unknown
    {
        DeltaDecision::Unknown
    } else {
        delta.overall_decision
    };
    let reason = if !baseline_bound || !candidate_bound {
        "SCANNER_SOURCE_COMMIT_DECLARATION_MISMATCH"
    } else if source.decision == Decision::Blocked {
        "LOCAL_SOURCE_INSPECTION_BLOCKED"
    } else if source.decision == Decision::Unknown {
        "LOCAL_SOURCE_INSPECTION_UNKNOWN"
    } else {
        "SCANNER_DELTA_AND_LOCAL_SOURCE_COMPOSED_NO_AUTHORITY"
    };
    let envelope = UpgradeDeltaEnvelope {
        schema: "tredven.upstream.source-scan-delta.v1",
        source,
        scanner_delta: delta,
        baseline_commit_binding: baseline_bound,
        candidate_commit_binding: candidate_bound,
        decision,
        reason,
        scanner_execution_attested: false,
        production_ready: false,
        action_authorized: false,
        performed_remote_queries: false,
        performed_mutations: false,
    };
    if format == "json" {
        serde_json::to_writer_pretty(&mut stdout, &envelope)
            .map_err(|_| "DELTA_JSON_WRITE_FAILED")?;
        writeln!(&mut stdout).map_err(|_| "DELTA_STDOUT_WRITE_FAILED")?;
    } else {
        write!(&mut stdout,"# Source-pinned local upgrade risk delta\n\nSource: {} to {}\nLocal changed paths: {}\nBaseline declared SHA matches: {}\nCandidate declared SHA matches: {}\nFinal: {:?} ({})\n\n{}",
            envelope.source.baseline_tag,envelope.source.candidate_tag,
            envelope.source.changed_paths_considered,baseline_bound,candidate_bound,
            decision,reason,envelope.scanner_delta.to_markdown())
            .map_err(|_|"DELTA_MARKDOWN_WRITE_FAILED")?;
    }
    Ok(delta_exit(decision))
}

fn run_attestation(mut args: impl Iterator<Item = String>, scan_mode: bool) -> Result<u8, String> {
    use tredven_upstream::attestation::{Policy, Verdict, verify_artifact};
    let mut artifact = None;
    let mut repo = None;
    let mut repo_id = None;
    let mut workflow = None;
    let mut source_ref = None;
    let mut commit = None;
    let mut bundle = None;
    let mut root = None;
    let mut online = false;
    let mut format = "json".to_owned();
    let mut predicate = None;
    let mut scanner = None;
    let mut subject = None;
    let mut policy_path = None;
    let mut format_seen = false;
    while let Some(key) = args.next() {
        if ["--help", "-h"].contains(&key.as_str()) {
            print!("{}", usage());
            return Ok(0);
        }
        if key == "--online" {
            if online {
                return Err("DUPLICATE_ATTESTATION_ONLINE".into());
            }
            online = true;
            continue;
        }
        let value = args.next().ok_or("MISSING_ATTESTATION_OPTION_VALUE")?;
        let place = match key.as_str() {
            "--artifact" => &mut artifact,
            "--policy" => &mut policy_path,
            "--repo" => &mut repo,
            "--repo-id" => &mut repo_id,
            "--signer-workflow" => &mut workflow,
            "--source-ref" => &mut source_ref,
            "--source-commit" => &mut commit,
            "--bundle" => &mut bundle,
            "--trusted-root" => &mut root,
            "--predicate-type" => &mut predicate,
            "--scanner" if scan_mode => &mut scanner,
            "--subject" if scan_mode => &mut subject,
            "--format" => {
                if format_seen {
                    return Err("DUPLICATE_ATTESTATION_FORMAT".into());
                }
                format_seen = true;
                format = value;
                continue;
            }
            _ => return Err("UNKNOWN_ATTESTATION_OPTION".into()),
        };
        if place.replace(value).is_some() {
            return Err("DUPLICATE_ATTESTATION_OPTION".into());
        }
    }
    if !["json", "markdown"].contains(&format.as_str()) {
        return Err("UNSUPPORTED_FORMAT".into());
    }
    let artifact = artifact.ok_or("MISSING_ATTESTATION_ARTIFACT")?;
    let p = if let Some(policy_path) = policy_path {
        if repo.is_some()
            || repo_id.is_some()
            || workflow.is_some()
            || source_ref.is_some()
            || commit.is_some()
            || bundle.is_some()
            || root.is_some()
            || predicate.is_some()
            || online
        {
            return Err("ATTESTATION_POLICY_SOURCE_CONFLICT".into());
        }
        let path = Path::new(&policy_path);
        let meta = fs::symlink_metadata(path).map_err(|_| "ATTESTATION_POLICY_FILE_UNAVAILABLE")?;
        if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 64 * 1024 {
            return Err("ATTESTATION_POLICY_NOT_BOUNDED_REGULAR_FILE".into());
        }
        let raw = fs::read(path).map_err(|_| "ATTESTATION_POLICY_READ_FAILED")?;
        if raw.len() > 64 * 1024 {
            return Err("ATTESTATION_POLICY_TOO_LARGE".into());
        }
        let mut p: Policy =
            serde_json::from_slice(&raw).map_err(|_| "ATTESTATION_POLICY_INVALID_JSON")?;
        let base = path.parent().unwrap_or(Path::new("."));
        if let Some(b) = p.bundle.as_mut() {
            if b.is_relative() {
                *b = base.join(&b);
            }
        }
        if let Some(root) = p.trusted_root.as_mut() {
            if root.is_relative() {
                *root = base.join(&root);
            }
        }
        p
    } else {
        Policy {
            repo: repo.ok_or("MISSING_ATTESTATION_REPO")?,
            repository_id: repo_id.ok_or("MISSING_ATTESTATION_REPO_ID")?,
            signer_workflow: workflow.ok_or("MISSING_ATTESTATION_SIGNER_WORKFLOW")?,
            source_ref: source_ref.ok_or("MISSING_ATTESTATION_SOURCE_REF")?,
            source_commit: commit.ok_or("MISSING_ATTESTATION_SOURCE_COMMIT")?,
            predicate_type: predicate.unwrap_or_else(|| "https://slsa.dev/provenance/v1".into()),
            bundle: bundle.map(std::path::PathBuf::from),
            trusted_root: root.map(std::path::PathBuf::from),
            online,
        }
    };
    let result = verify_artifact(Path::new(&artifact), &p);
    if scan_mode {
        use serde::Serialize;
        use sha2::Digest;
        use tredven_upstream::scanner::{
            ScanDecision, ScanSummary, ScannerFormat, inspect_scanner, valid_subject,
        };
        #[derive(Serialize)]
        struct AttestedScan {
            schema: &'static str,
            attestation: tredven_upstream::attestation::Report,
            scanner_summary: Option<ScanSummary>,
            decision: &'static str,
            reason: &'static str,
            scanner_execution_verified: bool,
            production_ready: bool,
            release_authorized: bool,
            action_authorized: bool,
        }
        let subject = subject.ok_or("MISSING_ATTESTED_SCAN_SUBJECT")?;
        if !valid_subject(&subject) {
            return Err("INVALID_ATTESTED_SCAN_SUBJECT".into());
        }
        let scanner = match scanner.ok_or("MISSING_ATTESTED_SCAN_FORMAT")?.as_str() {
            "trivy-json-v2" => ScannerFormat::TrivyJsonV2,
            "osv-scanner-json-v2" => ScannerFormat::OsvScannerJsonV2,
            _ => return Err("UNSUPPORTED_ATTESTED_SCAN_FORMAT".into()),
        };
        let (scan_result, decision, reason) = if result.verdict != Verdict::Verified {
            (
                None,
                "BLOCKED",
                "ARTIFACT_CRYPTOGRAPHIC_PROVENANCE_NOT_VERIFIED",
            )
        } else {
            // Analyze only file bytes that match the cryptographically
            // verified digest. A changed input must not gain review status.
            let bytes = bounded_scan_file(&artifact)?;
            let digest = format!("{:x}", sha2::Sha256::digest(&bytes));
            if result.artifact_sha256.as_deref() != Some(digest.as_str()) {
                (
                    None,
                    "BLOCKED",
                    "VERIFIED_ARTIFACT_CHANGED_BEFORE_SCANNER_PARSE",
                )
            } else {
                let parsed = inspect_scanner(&bytes, scanner, &subject);
                let verdict = match parsed.decision {
                    ScanDecision::Blocked => "BLOCKED",
                    ScanDecision::Unknown => "UNKNOWN",
                    ScanDecision::Review => "REVIEW",
                };
                (
                    Some(parsed),
                    verdict,
                    "VERIFIED_FILE_ORIGIN_SCAN_CONTENT_REVIEW_ONLY",
                )
            }
        };
        let envelope = AttestedScan {
            schema: "tredven.upstream.attested-scan-review.v1",
            attestation: result,
            scanner_summary: scan_result,
            decision,
            reason,
            scanner_execution_verified: false,
            production_ready: false,
            release_authorized: false,
            action_authorized: false,
        };
        let mut out = io::stdout().lock();
        if format == "json" {
            serde_json::to_writer_pretty(&mut out, &envelope)
                .map_err(|_| "ATTESTED_SCAN_JSON_FAILED")?;
            writeln!(&mut out).map_err(|_| "ATTESTED_SCAN_WRITE_FAILED")?;
        } else {
            writeln!(&mut out,"# Signed-file scanner review (not an upgrade approval)\n\nArtifact provenance: {:?}\nScanner decision: {}\nReason: {}\nScanner execution itself NOT VERIFIED. No deployment authority.\n",
                envelope.attestation.verdict,envelope.decision,envelope.reason)
                .map_err(|_|"ATTESTED_SCAN_MARKDOWN_FAILED")?;
        }
        return Ok(match decision {
            "BLOCKED" => 2,
            "UNKNOWN" => 3,
            _ => 0,
        });
    }
    let mut out = io::stdout().lock();
    if format == "json" {
        serde_json::to_writer_pretty(&mut out, &result).map_err(|_| "ATTESTATION_OUTPUT_FAILED")?;
        writeln!(&mut out).map_err(|_| "ATTESTATION_WRITE_FAILED")?;
    } else {
        write!(&mut out, "{}", result.markdown()).map_err(|_| "ATTESTATION_WRITE_FAILED")?;
    }
    Ok(if result.verdict == Verdict::Verified {
        0
    } else {
        2
    })
}

fn run_review(mut args: impl Iterator<Item = String>) -> Result<u8, String> {
    let mut path = None;
    let mut evidence_dir = None;
    let mut format = "json".to_owned();
    let mut seen_format = false;
    while let Some(arg) = args.next() {
        if ["--help", "-h"].contains(&arg.as_str()) {
            print!("{}", usage());
            return Ok(0);
        }
        let value = args.next().ok_or("MISSING_REVIEW_OPTION_VALUE")?;
        match arg.as_str() {
            "--evidence-dir" => {
                if evidence_dir.replace(value).is_some() {
                    return Err("DUPLICATE_EVIDENCE_DIR".into());
                }
            }
            "--config" => {
                if path.replace(value).is_some() {
                    return Err("DUPLICATE_REVIEW_CONFIG".into());
                }
            }
            "--format" => {
                if seen_format {
                    return Err("DUPLICATE_REVIEW_FORMAT".into());
                }
                seen_format = true;
                format = value;
            }
            _ => return Err("UNRECOGNIZED_REVIEW_OPTION".into()),
        }
    }
    if !["json", "markdown"].contains(&format.as_str()) {
        return Err("UNSUPPORTED_FORMAT".into());
    }
    let path = path.ok_or("MISSING_REVIEW_CONFIG")?;
    let path = Path::new(&path);
    let metadata = fs::symlink_metadata(path).map_err(|_| "REVIEW_CONFIG_FILE_MISSING")?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 128 * 1024 {
        return Err("REVIEW_CONFIG_NOT_BOUNDED_REGULAR_FILE".into());
    }
    let bytes = fs::read(path).map_err(|_| "REVIEW_CONFIG_FILE_UNREADABLE")?;
    let base = path.parent().unwrap_or(Path::new("."));
    let request = tredven_upstream::review::parse_config(&bytes, base)?;
    let outcome = tredven_upstream::review::review(request)?;
    if let Some(path) = evidence_dir {
        outcome.save_evidence(Path::new(&path))?;
    }
    let report = &outcome.report;
    let mut out = io::stdout().lock();
    if format == "json" {
        serde_json::to_writer_pretty(&mut out, &report).map_err(|_| "REVIEW_JSON_WRITE_FAILED")?;
        writeln!(&mut out).map_err(|_| "STDOUT_WRITE_FAILED")?;
    } else {
        write!(&mut out, "{}", report.markdown()).map_err(|_| "REVIEW_MARKDOWN_WRITE_FAILED")?;
    }
    Ok(match report.decision {
        "BLOCKED" => 2,
        "UNKNOWN" => 3,
        _ => 0,
    })
}

fn run() -> Result<u8, String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--help" | "-h") => {
            print!("{}", usage());
            return Ok(0);
        }
        Some("inspect") => {}
        Some("inspect-git") => return run_git(args),
        Some("inspect-plan") => return run_plan(args),
        Some("inspect-scan") => return run_scan(args),
        Some("inspect-upgrade") => return run_upgrade(args),
        Some("inspect-delta") => return run_delta(args, false),
        Some("inspect-upgrade-delta") => return run_delta(args, true),
        Some("review-upgrade") => return run_review(args),
        Some("verify-attestation") => return run_attestation(args, false),
        Some("inspect-attested-scan") => return run_attestation(args, true),
        Some("inspect-contract") => return run_contract(args),
        _ => return Err(usage().trim_end().into()),
    };

    let mut input_path = None;
    let mut from_stdin = false;
    let mut format = "json".to_owned();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => {
                if input_path.is_some() || from_stdin {
                    return Err("INPUT_SPECIFIED_MORE_THAN_ONCE".into());
                }
                input_path = Some(args.next().ok_or("MISSING_INPUT_PATH")?);
            }
            "--stdin" => {
                if input_path.is_some() || from_stdin {
                    return Err("INPUT_SPECIFIED_MORE_THAN_ONCE".into());
                }
                from_stdin = true;
            }
            "--format" => format = args.next().ok_or("MISSING_FORMAT")?,
            "--help" | "-h" => {
                print!("{}", usage());
                return Ok(0);
            }
            _ => return Err("UNRECOGNIZED_ARGUMENT".into()),
        }
    }
    if !["json", "markdown"].contains(&format.as_str()) {
        return Err("UNSUPPORTED_FORMAT".into());
    }

    let input = if let Some(path) = input_path {
        let path = Path::new(&path);
        let metadata = fs::symlink_metadata(path).map_err(|_| "INPUT_FILE_UNAVAILABLE")?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_INPUT_BYTES {
            return Err("INPUT_MUST_BE_BOUNDED_REGULAR_FILE".into());
        }
        fs::read_to_string(path).map_err(|_| "INPUT_FILE_READ_FAILED")?
    } else if from_stdin {
        let mut bytes = Vec::new();
        io::stdin()
            .take(MAX_INPUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "STDIN_READ_FAILED")?;
        if bytes.len() as u64 > MAX_INPUT_BYTES {
            return Err("INPUT_TOO_LARGE".into());
        }
        String::from_utf8(bytes).map_err(|_| "INPUT_NOT_UTF8")?
    } else {
        return Err("MISSING_INPUT".into());
    };

    let request: PreflightInput = serde_json::from_str(&input).map_err(|_| "INVALID_INPUT_JSON")?;
    let report = inspect(request)?;
    emit(&report, &format)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(message) => fail(&message),
    }
}
