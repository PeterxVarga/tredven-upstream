use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static I: AtomicUsize = AtomicUsize::new(0);
struct Scratch {
    dir: PathBuf,
}
impl Scratch {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "tredven-native-scan-{}-{now}-{}",
            std::process::id(),
            I.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }
    fn fixture(&self, name: &str) -> PathBuf {
        let path = self.dir.join("scan.json");
        let real = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/scanner")
            .join(name);
        fs::copy(real, &path).unwrap();
        path
    }
    fn run(&self, path: &Path, format: &str, subject: &str, markdown: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"));
        cmd.args(["inspect-scan", "--input"]).arg(path).args([
            "--scanner",
            format,
            "--subject",
            subject,
        ]);
        if markdown {
            cmd.args(["--format", "markdown"]);
        }
        cmd.output().unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
const TRIVY: &str = "example/app@sha256:synthetic-candidate";
#[test]
fn standalone_high_severity_blocks_and_denies_claim_of_authority() {
    let f = Scratch::new();
    let p = f.fixture("trivy-critical.json");
    let out = f.run(&p, "trivy-json-v2", TRIVY, false);
    assert_eq!(out.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["decision"], "BLOCKED");
    assert_eq!(r["high_or_critical_occurrences"], 1);
    assert_eq!(r["scanner_execution_attested"], false);
    assert_eq!(r["source_commit_attested_by_scanner"], false);
    assert_eq!(r["production_ready"], false);
}
#[test]
fn standalone_trivy_clean_is_review_only() {
    let f = Scratch::new();
    let p = f.fixture("trivy-clean.json");
    let out = f.run(&p, "trivy-json-v2", TRIVY, true);
    assert_eq!(out.status.code(), Some(0));
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("Decision: Review"));
    assert!(s.contains("scanner execution NOT ATTESTED"));
}
#[test]
fn empty_scan_is_unknown_and_exit_three() {
    let f = Scratch::new();
    let p = f.fixture("trivy-empty.json");
    let out = f.run(&p, "trivy-json-v2", TRIVY, false);
    assert_eq!(out.status.code(), Some(3));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["decision"], "UNKNOWN");
}
#[test]
fn osv_findings_block_no_severity_guessing() {
    let f = Scratch::new();
    let p = f.fixture("osv-vulnerable.json");
    let out = f.run(&p, "osv-scanner-json-v2", "Cargo.lock", false);
    assert_eq!(out.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["decision"], "BLOCKED");
    assert_eq!(r["reason"], "OSV_VULNERABILITIES_REPORTED");
}
#[test]
fn osv_empty_cannot_be_falsely_green() {
    let f = Scratch::new();
    let p = f.fixture("osv-empty.json");
    let out = f.run(&p, "osv-scanner-json-v2", "Cargo.lock", false);
    assert_eq!(out.status.code(), Some(3));
}
#[test]
fn file_symlink_and_unknown_scanner_are_rejected() {
    let f = Scratch::new();
    let p = f.fixture("trivy-clean.json");
    let wrong = f.run(&p, "invented-scanner-v4", TRIVY, false);
    assert_eq!(wrong.status.code(), Some(1));
    #[cfg(unix)]
    {
        let symlink = f.dir.join("symlink.json");
        std::os::unix::fs::symlink(&p, &symlink).unwrap();
        let out = f.run(&symlink, "trivy-json-v2", TRIVY, false);
        assert_eq!(out.status.code(), Some(1));
        assert!(
            String::from_utf8(out.stderr)
                .unwrap()
                .contains("REGULAR_FILE")
        );
    }
}
#[test]
fn no_shell_or_network_access_and_no_scanner_run() {
    let f = Scratch::new();
    let p = f.fixture("trivy-clean.json");
    let out = f.run(&p, "trivy-json-v2", TRIVY, false);
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["scanner_execution_attested"], false);
    assert_eq!(r["complete_scan_coverage_attested"], false);
    assert_eq!(r["source_commit_attested_by_scanner"], false);
}
