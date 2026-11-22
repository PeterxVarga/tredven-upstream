//! One-command source-bound, scanner-observed upgrade assessment.
//! External tools stay upstream: Git reads local objects, OSV performs scans,
//! GitHub CLI verifies already-signed reports. No secrets, deployment or CI.
use crate::PreflightReport;
use crate::attestation::{self, Policy, Verdict};
use crate::delta::{self, DeltaDecision, ScanDeltaReport};
use crate::git_source::inspect_local_git;
use crate::lockfile;
use crate::scanner::{self, ScanDecision, ScanSummary, ScannerFormat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const SCHEMA: &str = "tredven.upstream.upgrade-review.v1";
const MAX_REPORT: u64 = 8 * 1024 * 1024;
const MAX_BIN: u64 = 128 * 1024 * 1024;
const MAX_CONFIG: u64 = 128 * 1024;
const MAX_LOCK: usize = 2_000_000;
const SCAN_TIMEOUT: Duration = Duration::from_secs(110);
static NONCE: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: String,
    pub project: String,
    pub repo: PathBuf,
    pub baseline_tag: String,
    pub candidate_tag: String,
    pub scan: ScanInput,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ScanInput {
    ExistingReports {
        format: ScannerFormat,
        subject: String,
        baseline: PathBuf,
        candidate: PathBuf,
        #[serde(default)]
        baseline_attestation: Option<Box<Policy>>,
        #[serde(default)]
        candidate_attestation: Option<Box<Policy>>,
    },
    LocalOsvLockfile {
        lockfile: String,
        binary: PathBuf,
        binary_sha256: String,
        allow_public_osv_network: bool,
    },
    /// A GH-signed, workflow-authored receipt binds separately downloaded
    /// scan JSON bytes and local Git source lockfile snapshots. The signer
    /// repository is deliberately distinct from the scanned target repo.
    SignedCiReceipt {
        receipt: PathBuf,
        baseline: PathBuf,
        candidate: PathBuf,
        scanned_repo: String,
        scanner_version: String,
        scanner_binary_sha256: String,
        attestation: Box<Policy>,
    },
}

#[derive(Debug, Serialize)]
pub struct Evidence {
    pub report_sha256: String,
    pub input_lockfile_sha256: Option<String>,
    pub scanner: ScanSummary,
    pub local_scanner_process_exit: Option<i32>,
    pub local_execution_observed: bool,
    pub signed_file_provenance: Option<attestation::Report>,
    pub scanner_execution_cryptographically_attested: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub project: String,
    pub source: PreflightReport,
    pub scan_mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analyzed_lockfile: Option<String>,
    pub scanner_binary_sha256: Option<String>,
    pub baseline: Evidence,
    pub candidate: Evidence,
    pub delta: ScanDeltaReport,
    pub decision: &'static str,
    pub reason: &'static str,
    pub source_remote_publisher_attested: bool,
    pub scanner_execution_cryptographically_attested: bool,
    pub all_artifact_signatures_verified: bool,
    pub signed_ci_run: Option<crate::ci_receipt::CiReceiptEvidence>,
    pub public_osv_api_access_permitted: bool,
    pub performed_git_remote_queries: bool,
    pub performed_provider_mutations: bool,
    pub production_ready: bool,
    pub release_authorized: bool,
    pub action_authorized: bool,
}

impl Report {
    pub fn markdown(&self) -> String {
        let n = |v: Option<usize>| v.map_or("UNKNOWN".into(), |n| n.to_string());
        let mut summary = format!(
            "# Verified upgrade review — not a deployment grant\n\n\
             Project: {}\nSource tags: {} → {}\nCommits: {} → {}\nChanged paths: {}\n\
             Scanner mode: {}\nBaseline: {:?}, candidate: {:?}\n\
             New findings: {}, resolved: {}, persistent: {}, escalations: {}\n\
             Delta: {:?}\nDecision: **{}** ({})\n\
             Locally observed scanner runs: {} / {}\n\
             Signed artifact provenance: {}\nCryptographically attested scanner execution: NO\n\
             Remote source publisher attested: NO\nProduction ready: NO\nNo deployment/release authority.\n",
            self.project,
            self.source.baseline_tag,
            self.source.candidate_tag,
            self.source.baseline_commit.as_deref().unwrap_or("UNKNOWN"),
            self.source.candidate_commit.as_deref().unwrap_or("UNKNOWN"),
            self.source.changed_paths_considered,
            self.scan_mode,
            self.baseline.scanner.decision,
            self.candidate.scanner.decision,
            n(self.delta.new_occurrences),
            n(self.delta.resolved_occurrences),
            n(self.delta.persistent_occurrences),
            n(self.delta.severity_escalations),
            self.delta.delta_decision,
            self.decision,
            self.reason,
            self.baseline.local_execution_observed,
            self.candidate.local_execution_observed,
            self.all_artifact_signatures_verified
        );
        if let Some(lockfile) = self.analyzed_lockfile.as_deref() {
            summary.push_str(&format!(
                "\nAnalyzed dependency file: {lockfile} (one selected file, NOT whole-repository coverage)\n"
            ));
        }
        if self.delta.comparable_scan_scope {
            if !self.delta.new_sample.is_empty() || !self.delta.resolved_sample.is_empty() {
                summary.push_str("\nSpecific findings (bounded sample; not a release approval):\n");
            }
            for item in &self.delta.new_sample {
                summary.push_str(&format!(
                    "- New {} {} [{}] ({})\n",
                    item.category, item.id, item.package, item.severity
                ));
            }
            for item in &self.delta.resolved_sample {
                summary.push_str(&format!(
                    "- Resolved {} {} [{}] ({})\n",
                    item.category, item.id, item.package, item.severity
                ));
            }
            if self.delta.resolved_occurrences.unwrap_or(0) > self.delta.resolved_sample.len() {
                summary.push_str("- More resolved findings omitted\n");
            }
            if self.delta.findings_sample_truncated {
                summary.push_str("- More new findings omitted\n");
            }
        }
        summary
    }
}

/// Verified source/scan receipts and the raw bytes needed to reproduce the
/// diagnostic outcome. Contents may contain sensitive advisory data; writing
/// the evidence directory is an explicit caller action, never the default.
pub struct ReviewOutput {
    pub report: Report,
    pub baseline_json: Vec<u8>,
    pub candidate_json: Vec<u8>,
    pub baseline_lockfile: Option<Vec<u8>>,
    pub candidate_lockfile: Option<Vec<u8>>,
    pub signed_ci_receipt: Option<Vec<u8>>,
}
impl ReviewOutput {
    pub fn save_evidence(&self, path: &Path) -> Result<(), String> {
        if path.exists() || fs::symlink_metadata(path).is_ok() {
            return Err("EVIDENCE_DIR_EXISTS_NO_OVERWRITE".into());
        }
        let name = path
            .file_name()
            .and_then(|x| x.to_str())
            .ok_or("INVALID_EVIDENCE_DIR_BASENAME")?;
        if name.is_empty()
            || name.len() > 80
            || name == "."
            || name == ".."
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err("INVALID_EVIDENCE_DIR_BASENAME".into());
        }
        let parent = path.parent().unwrap_or(Path::new("."));
        let meta = fs::symlink_metadata(parent).map_err(|_| "EVIDENCE_DIR_PARENT_UNAVAILABLE")?;
        if !meta.file_type().is_dir() {
            return Err("EVIDENCE_DIR_PARENT_NOT_REAL_DIRECTORY".into());
        }
        if self.report.baseline.report_sha256 != sha(&self.baseline_json)
            || self.report.candidate.report_sha256 != sha(&self.candidate_json)
        {
            return Err("EVIDENCE_REPORT_BYTES_NOT_QUALIFIED".into());
        }
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        let report = serde_json::to_vec_pretty(&self.report)
            .map_err(|_| "EVIDENCE_RECEIPT_SERIALIZATION_FAILED")?;
        if let Some(bytes) = self.baseline_lockfile.as_ref() {
            if self.report.baseline.input_lockfile_sha256.as_deref() != Some(sha(bytes).as_str()) {
                return Err("BASELINE_LOCKFILE_EVIDENCE_NOT_QUALIFIED".into());
            }
        }
        if let Some(bytes) = self.candidate_lockfile.as_ref() {
            if self.report.candidate.input_lockfile_sha256.as_deref() != Some(sha(bytes).as_str()) {
                return Err("CANDIDATE_LOCKFILE_EVIDENCE_NOT_QUALIFIED".into());
            }
        }
        // Preserve legacy Cargo.lock receipt names for signed-CI mode;
        // for local multi-ecosystem scans write the selected source basename.
        let selected_basename = self
            .report
            .analyzed_lockfile
            .as_deref()
            .unwrap_or("Cargo.lock")
            .rsplit('/')
            .next()
            .ok_or("EVIDENCE_LOCKFILE_NAME_INVALID")?;
        let baseline_name = format!("baseline.{selected_basename}");
        let candidate_name = format!("candidate.{selected_basename}");
        let mut entries = vec![
            ("baseline.scanner.json", self.baseline_json.as_slice()),
            ("candidate.scanner.json", self.candidate_json.as_slice()),
            ("review.json", report.as_slice()),
        ];
        if let Some(bytes) = self.baseline_lockfile.as_ref() {
            entries.push((baseline_name.as_str(), bytes.as_slice()));
        }
        if let Some(bytes) = self.candidate_lockfile.as_ref() {
            entries.push((candidate_name.as_str(), bytes.as_slice()));
        }
        if let Some(bytes) = self.signed_ci_receipt.as_ref() {
            if self
                .report
                .signed_ci_run
                .as_ref()
                .map(|x| x.receipt_sha256.as_str())
                != Some(sha(bytes).as_str())
            {
                return Err("SIGNED_CI_RECEIPT_BYTES_NOT_QUALIFIED".into());
            }
            entries.push(("ci-run.receipt.json", bytes.as_slice()));
        }
        builder
            .create(path)
            .map_err(|_| "EVIDENCE_DIR_CREATE_FAILED")?;
        let mut sums = String::new();
        for (filename, bytes) in entries {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(path.join(filename))
                .map_err(|_| "EVIDENCE_FILE_CREATE_FAILED")?;
            use std::io::Write;
            file.write_all(bytes)
                .map_err(|_| "EVIDENCE_FILE_WRITE_FAILED")?;
            sums.push_str(&format!("{}  {}\n", sha(bytes), filename));
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        options
            .open(path.join("SHA256SUMS"))
            .map_err(|_| "EVIDENCE_SUMS_CREATE_FAILED")?
            .write_all(sums.as_bytes())
            .map_err(|_| "EVIDENCE_SUMS_WRITE_FAILED")?;
        Ok(())
    }
}

fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn bounded_file(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "SCAN_ARTIFACT_UNAVAILABLE")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > max {
        return Err("SCAN_ARTIFACT_NOT_BOUNDED_REGULAR_FILE".into());
    }
    let raw = fs::read(path).map_err(|_| "SCAN_ARTIFACT_NOT_READABLE")?;
    if raw.is_empty() || raw.len() as u64 > max {
        return Err("SCAN_ARTIFACT_SIZE_CHANGED".into());
    }
    Ok(raw)
}

fn binary_digest(path: &Path, expected: &str) -> Result<String, String> {
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("SCANNER_BINARY_SHA256_PIN_INVALID".into());
    }
    if !path.is_absolute() {
        return Err("SCANNER_BINARY_ABSOLUTE_PATH_REQUIRED".into());
    }
    let meta = fs::symlink_metadata(path).map_err(|_| "SCANNER_BINARY_UNAVAILABLE")?;
    if !meta.file_type().is_file() || meta.len() > MAX_BIN || meta.len() == 0 {
        return Err("SCANNER_BINARY_NOT_BOUNDED_REGULAR_FILE".into());
    }
    let mut f = File::open(path).map_err(|_| "SCANNER_BINARY_UNREADABLE")?;
    let mut state = Sha256::new();
    let mut buf = [0u8; 16384];
    loop {
        let n = f.read(&mut buf).map_err(|_| "SCANNER_BINARY_READ_FAILED")?;
        if n == 0 {
            break;
        }
        state.update(&buf[..n]);
    }
    let got = format!("{:x}", state.finalize());
    if !got.eq_ignore_ascii_case(expected) {
        return Err("SCANNER_BINARY_SHA256_MISMATCH".into());
    }
    Ok(got)
}

struct Scratch {
    dir: PathBuf,
}
impl Scratch {
    fn new() -> Result<Self, String> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "LOCAL_CLOCK_UNAVAILABLE")?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "tredven-r10-{}-{}-{}",
            std::process::id(),
            stamp,
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        // Create directory with private permissions before passing it to an
        // external tool. Never use a user-selected output folder for cleanup.
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&dir)
            .map_err(|_| "SCAN_PRIVATE_TEMP_DIRECTORY_FAILED")?;
        Ok(Self { dir })
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn run_osv(
    binary: &Path,
    scratch: &Scratch,
    source_path: &str,
    lockfile: &[u8],
) -> Result<(Vec<u8>, i32, String), String> {
    if lockfile.is_empty() || lockfile.len() > MAX_LOCK {
        return Err("LOCKFILE_BYTES_OUT_OF_BOUNDS".into());
    }
    if !lockfile::supported(source_path) {
        return Err("UNSUPPORTED_OR_UNSAFE_LOCKFILE_PATH".into());
    }
    let lockpath = scratch.dir.join(source_path);
    if let Some(parent) = lockpath.parent() {
        fs::create_dir_all(parent).map_err(|_| "LOCKFILE_SNAPSHOT_PARENT_CREATE_FAILED")?;
    }
    fs::write(&lockpath, lockfile).map_err(|_| "LOCKFILE_SNAPSHOT_WRITE_FAILED")?;
    let stdout = scratch.dir.join("scanner-stdout.json");
    let stderr = scratch.dir.join("scanner-stderr.txt");
    let out = File::create(&stdout).map_err(|_| "SCANNER_OUTPUT_CREATE_FAILED")?;
    let err = File::create(&stderr).map_err(|_| "SCANNER_ERROR_LOG_CREATE_FAILED")?;
    // Never execute Cargo, a source repository hook or OSV call analysis.
    // The scanner is confined to one extracted Cargo.lock in a new directory.
    // Allow network access ONLY when the user has explicitly approved public
    // OSV API queries; do not forward caller credentials or HOME.
    let mut cmd = Command::new(binary);
    cmd.current_dir(&scratch.dir)
        .env_clear()
        .env("HOME", &scratch.dir)
        .env("XDG_CACHE_HOME", &scratch.dir)
        .env("XDG_CONFIG_HOME", &scratch.dir)
        .env("PATH", "/usr/bin:/bin")
        .args([
            "scan",
            "source",
            "--lockfile",
            source_path,
            "--format",
            "json",
            "--all-packages",
            "--no-resolve",
            "--verbosity",
            "error",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    let mut child = cmd
        .spawn()
        .map_err(|_| "OSV_SCANNER_PROCESS_NOT_STARTABLE")?;
    let start = Instant::now();
    let exit = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                break status
                    .code()
                    .ok_or("OSV_SCANNER_TERMINATED_WITHOUT_EXIT_CODE")?;
            }
            Ok(None) => {
                if start.elapsed() > SCAN_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("OSV_SCANNER_TIMED_OUT".into());
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("OSV_SCANNER_PROCESS_STATUS_FAILED".into());
            }
        }
    };
    // OSV: 0 = scan completed, no findings; 1 = completed with findings.
    // Other statuses and any non-JSON output are not evidence of a scan.
    if exit != 0 && exit != 1 {
        return Err("OSV_SCANNER_FAILED_NO_QUALIFIED_REPORT".into());
    }
    let report = bounded_file(&stdout, MAX_REPORT)?;
    if serde_json::from_slice::<serde_json::Value>(&report).is_err() {
        return Err("OSV_SCANNER_DID_NOT_WRITE_JSON".into());
    }
    let observed_path = lockpath.to_string_lossy();
    let decoded =
        scanner::inspect_scanner(&report, ScannerFormat::OsvScannerJsonV2, &observed_path);
    if (exit == 1 && decoded.vulnerability_occurrences == 0)
        || (exit == 0 && decoded.vulnerability_occurrences > 0)
    {
        return Err("OSV_EXIT_CODE_AND_REPORT_FINDINGS_CONTRADICT".into());
    }
    if fs::read(&lockpath).map_err(|_| "SNAPSHOT_READBACK_FAILED")? != lockfile {
        return Err("SCANNER_MODIFIED_PINNED_LOCKFILE".into());
    }
    Ok((report, exit, lockpath.to_string_lossy().into_owned()))
}
fn validate_config(config: &Config) -> Result<(), String> {
    if config.schema != SCHEMA {
        return Err("INVALID_UPGRADE_REVIEW_SCHEMA".into());
    }
    if config.project.is_empty()
        || config.project.len() > 100
        || !config
            .project
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err("INVALID_UPGRADE_REVIEW_PROJECT".into());
    }
    match &config.scan {
        ScanInput::LocalOsvLockfile {
            lockfile,
            allow_public_osv_network,
            binary_sha256,
            ..
        } => {
            if !lockfile::supported(lockfile) {
                return Err("UNSUPPORTED_OR_UNSAFE_LOCKFILE_PATH".into());
            }
            if !allow_public_osv_network {
                return Err("OSV_PUBLIC_API_NETWORK_NOT_EXPLICITLY_APPROVED".into());
            }
            if binary_sha256.len() != 64 || !binary_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("SCANNER_BINARY_SHA256_PIN_INVALID".into());
            }
        }
        ScanInput::ExistingReports { subject, .. } => {
            if !scanner::valid_subject(subject) {
                return Err("INVALID_EXISTING_REPORT_SUBJECT".into());
            }
        }
        ScanInput::SignedCiReceipt {
            scanned_repo,
            scanner_version,
            scanner_binary_sha256,
            ..
        } => {
            if !valid_repo_pair(scanned_repo) {
                return Err("INVALID_SIGNED_CI_SCANNED_REPOSITORY".into());
            }
            if scanner_version != "2.7.1" {
                return Err("UNQUALIFIED_SIGNED_CI_SCANNER_VERSION".into());
            }
            if scanner_binary_sha256.len() != 64
                || !scanner_binary_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err("INVALID_SIGNED_CI_SCANNER_BINARY_DIGEST".into());
            }
        }
    }
    Ok(())
}
fn valid_repo_pair(s: &str) -> bool {
    let mut parts = s.split('/');
    let good = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && s != "."
            && s != ".."
            && !s.contains("..")
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    };
    parts.next().is_some_and(good) && parts.next().is_some_and(good) && parts.next().is_none()
}
pub fn parse_config(raw: &[u8], base: &Path) -> Result<Config, String> {
    if raw.is_empty() || raw.len() > MAX_CONFIG as usize {
        return Err("UPGRADE_REVIEW_CONFIG_SIZE_INVALID".into());
    }
    let mut config: Config =
        serde_json::from_slice(raw).map_err(|_| "INVALID_UPGRADE_REVIEW_CONFIG_JSON")?;
    validate_config(&config)?;
    if config.repo.is_relative() {
        config.repo = base.join(&config.repo);
    }
    let resolve = |p: &mut PathBuf| {
        if p.is_relative() {
            *p = base.join(&p);
        }
    };
    match &mut config.scan {
        ScanInput::LocalOsvLockfile { binary, .. } => resolve(binary),
        ScanInput::SignedCiReceipt {
            receipt,
            baseline,
            candidate,
            attestation,
            ..
        } => {
            resolve(receipt);
            resolve(baseline);
            resolve(candidate);
            for p in [&mut attestation.bundle, &mut attestation.trusted_root]
                .into_iter()
                .flatten()
            {
                resolve(p);
            }
        }
        ScanInput::ExistingReports {
            baseline,
            candidate,
            baseline_attestation,
            candidate_attestation,
            ..
        } => {
            resolve(baseline);
            resolve(candidate);
            for policy in [baseline_attestation, candidate_attestation]
                .into_iter()
                .flatten()
            {
                for p in [&mut policy.bundle, &mut policy.trusted_root]
                    .into_iter()
                    .flatten()
                {
                    resolve(p);
                }
            }
        }
    }
    Ok(config)
}
pub fn review(config: Config) -> Result<ReviewOutput, String> {
    validate_config(&config)?;
    let source = inspect_local_git(
        &config.repo,
        &config.project,
        &config.baseline_tag,
        &config.candidate_tag,
    )?;
    let base_commit = source
        .baseline_commit
        .as_ref()
        .ok_or("BASELINE_GIT_COMMIT_NOT_OBSERVED")?;
    let candidate_commit = source
        .candidate_commit
        .as_ref()
        .ok_or("CANDIDATE_GIT_COMMIT_NOT_OBSERVED")?;
    if let ScanInput::SignedCiReceipt {
        receipt,
        baseline,
        candidate,
        scanned_repo,
        scanner_version,
        scanner_binary_sha256,
        attestation,
    } = &config.scan
    {
        return crate::ci_receipt::review_signed_ci(
            &config.repo,
            source,
            &config.project,
            receipt,
            baseline,
            candidate,
            scanned_repo,
            scanner_version,
            scanner_binary_sha256,
            attestation,
        );
    }
    let analyzed_lockfile = match &config.scan {
        ScanInput::LocalOsvLockfile { lockfile, .. } => Some(lockfile.to_owned()),
        _ => None,
    };
    let (
        scan_mode,
        format,
        subject,
        base_report,
        candidate_report,
        base_lock,
        candidate_lock,
        base_exit,
        candidate_exit,
        base_attest,
        candidate_attest,
        binary_sha,
        local_observed,
        network_queries,
        base_lock_bytes,
        candidate_lock_bytes,
    ) = match config.scan {
        ScanInput::ExistingReports {
            format,
            subject,
            baseline,
            candidate,
            baseline_attestation,
            candidate_attestation,
        } => {
            let base_raw = bounded_file(&baseline, MAX_REPORT)?;
            let candidate_raw = bounded_file(&candidate, MAX_REPORT)?;
            let attest = |p: Option<Box<Policy>>,
                          path: &Path,
                          tag: &str,
                          commit: &str|
             -> Option<attestation::Report> {
                p.map(|pol| {
                    // A signature for another ref/commit is never used as
                    // a false proof for the observed local source version.
                    if pol.source_commit != commit || pol.source_ref != format!("refs/tags/{tag}") {
                        attestation::reject_policy(
                            &pol,
                            "ATTESTATION_SOURCE_TAG_COMMIT_NOT_THE_SELECTED_UPGRADE",
                        )
                    } else {
                        attestation::verify_artifact(path, &pol)
                    }
                })
            };
            let b = attest(
                baseline_attestation,
                &baseline,
                &config.baseline_tag,
                base_commit,
            );
            let c = attest(
                candidate_attestation,
                &candidate,
                &config.candidate_tag,
                candidate_commit,
            );
            (
                "existing-reports",
                format,
                subject,
                base_raw,
                candidate_raw,
                None,
                None,
                None,
                None,
                b,
                c,
                None,
                false,
                false,
                None,
                None,
            )
        }
        ScanInput::LocalOsvLockfile {
            lockfile,
            binary,
            binary_sha256,
            allow_public_osv_network,
        } => {
            if !lockfile::supported(&lockfile) || !allow_public_osv_network {
                return Err("OSV_PUBLIC_SCANNER_POLICY_NOT_APPROVED".into());
            }
            let digest = binary_digest(&binary, &binary_sha256)?;
            let scratch = Scratch::new()?;
            let base_input = lockfile::snapshot(&config.repo, base_commit, &lockfile)?;
            let cand_input = lockfile::snapshot(&config.repo, candidate_commit, &lockfile)?;
            if base_input.is_empty() || cand_input.is_empty() {
                return Err("LOCKFILE_NOT_IN_BOTH_PINNED_SOURCE_COMMITS".into());
            }
            let (base_scan, bexit, path) = run_osv(&binary, &scratch, &lockfile, &base_input)?;
            let (candidate_scan, cexit, cpath) =
                run_osv(&binary, &scratch, &lockfile, &cand_input)?;
            if path != cpath {
                return Err("OSV_SCANNED_DIFFERENT_FILE_PATHS".into());
            }
            // The scanner itself emits its actual *absolute* source path.
            // The exact same path is deliberately used sequentially for
            // comparable reports, while input SHA pins remain independent.
            (
                "local-osv-lockfile",
                ScannerFormat::OsvScannerJsonV2,
                path,
                base_scan,
                candidate_scan,
                Some(sha(&base_input)),
                Some(sha(&cand_input)),
                Some(bexit),
                Some(cexit),
                None,
                None,
                Some(digest),
                true,
                true,
                Some(base_input),
                Some(cand_input),
            )
        }
        ScanInput::SignedCiReceipt { .. } => unreachable!("signed CI handled by early branch"),
    };
    let baseline = scanner::inspect_scanner(&base_report, format, &subject);
    let candidate = scanner::inspect_scanner(&candidate_report, format, &subject);
    let delta = delta::compare_reports(&base_report, &candidate_report, format, &subject);
    let base_verified = base_attest
        .as_ref()
        .is_some_and(|r| r.verdict == Verdict::Verified);
    let candidate_verified = candidate_attest
        .as_ref()
        .is_some_and(|r| r.verdict == Verdict::Verified);
    let signed = base_verified && candidate_verified;
    let blocker = candidate.decision == ScanDecision::Blocked
        || delta.overall_decision == DeltaDecision::Blocked;
    let provenance_failure = [base_attest.as_ref(), candidate_attest.as_ref()]
        .into_iter()
        .flatten()
        .any(|r| r.verdict == Verdict::Blocked);
    let (decision, reason) = if provenance_failure {
        ("BLOCKED", "PROVIDED_PROVENANCE_CANNOT_BE_VERIFIED")
    } else if blocker {
        ("BLOCKED", "CANDIDATE_SECURITY_FINDING_OR_DELTA_BLOCKER")
    } else if delta.overall_decision == DeltaDecision::Unknown
        || baseline.decision == ScanDecision::Unknown
        || candidate.decision == ScanDecision::Unknown
    {
        ("UNKNOWN", "SCANNER_COMPARISON_OR_COVERAGE_INCOMPLETE")
    } else if !local_observed && !signed {
        (
            "UNKNOWN",
            "USER_SUPPLIED_REPORTS_HAVE_NO_VERIFIED_PROVENANCE",
        )
    } else if local_observed {
        ("REVIEW", "TWO_LOCAL_OSV_RUNS_OBSERVED_NOT_SIGNED")
    } else {
        (
            "REVIEW",
            "BOTH_SCAN_REPORT_FILES_SIGNED_SCANNER_EXECUTION_NOT_ATTESTED",
        )
    };
    let base_evidence = Evidence {
        report_sha256: sha(&base_report),
        input_lockfile_sha256: base_lock,
        scanner: baseline,
        local_scanner_process_exit: base_exit,
        local_execution_observed: local_observed,
        signed_file_provenance: base_attest,
        scanner_execution_cryptographically_attested: false,
    };
    let candidate_evidence = Evidence {
        report_sha256: sha(&candidate_report),
        input_lockfile_sha256: candidate_lock,
        scanner: candidate,
        local_scanner_process_exit: candidate_exit,
        local_execution_observed: local_observed,
        signed_file_provenance: candidate_attest,
        scanner_execution_cryptographically_attested: false,
    };
    let report = Report {
        schema: SCHEMA,
        project: config.project,
        source,
        scan_mode,
        analyzed_lockfile,
        scanner_binary_sha256: binary_sha,
        baseline: base_evidence,
        candidate: candidate_evidence,
        delta,
        decision,
        reason,
        source_remote_publisher_attested: false,
        scanner_execution_cryptographically_attested: false,
        all_artifact_signatures_verified: signed,
        signed_ci_run: None,
        public_osv_api_access_permitted: network_queries,
        performed_git_remote_queries: false,
        performed_provider_mutations: false,
        production_ready: false,
        release_authorized: false,
        action_authorized: false,
    };
    Ok(ReviewOutput {
        report,
        baseline_json: base_report,
        candidate_json: candidate_report,
        baseline_lockfile: base_lock_bytes,
        candidate_lockfile: candidate_lock_bytes,
        signed_ci_receipt: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_implicit_scanner_network_and_unknown_modes() {
        let raw=br#"{"schema":"tredven.upstream.upgrade-review.v1","project":"public","repo":".","baseline_tag":"v1.0","candidate_tag":"v1.1","scan":{"mode":"local-osv-lockfile","lockfile":"Cargo.lock","binary":"/bin/false","binary_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allow_public_osv_network":false}}"#;
        assert_eq!(
            parse_config(raw, Path::new(".")).unwrap_err(),
            "OSV_PUBLIC_API_NETWORK_NOT_EXPLICITLY_APPROVED"
        );
        assert!(parse_config(br#"{"schema":"oops"}"#, Path::new(".")).is_err());
    }
    #[test]
    fn binary_hash_mismatch_blocks_local_process_before_execution() {
        let tmp = Scratch::new().unwrap();
        let bin = tmp.dir.join("fake-osv");
        fs::write(&bin, b"fake").unwrap();
        assert_eq!(
            binary_digest(&bin, &"0".repeat(64)).unwrap_err(),
            "SCANNER_BINARY_SHA256_MISMATCH"
        );
    }
}
