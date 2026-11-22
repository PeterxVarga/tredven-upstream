//! Source-bound system upgrade impact, evidence gate and local-only staging E2E.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const OLD: &str = r#"services:
  db:
    image: postgres:16
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck: {test: [CMD, pg_isready]}
  api:
    image: example/api:1
    depends_on: [db]
  worker:
    image: example/worker:1
    depends_on:
      api: {condition: service_started}
"#;
const NEW: &str = r#"services:
  db:
    image: postgres:17
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck: {test: [CMD, pg_isready]}
  api:
    image: example/api:1
    depends_on: [db]
  worker:
    image: example/worker:1
    depends_on:
      api: {condition: service_started}
"#;

struct Fixture {
    root: PathBuf,
    repo: PathBuf,
    base: String,
    candidate: String,
    hash: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
impl Fixture {
    fn git(&self, args: &[&str]) -> String {
        let o = Command::new("git")
            .arg("-C")
            .arg(&self.repo)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap().trim().into()
    }
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "r27-systems-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let repo = root.join("project");
        fs::create_dir_all(&repo).unwrap();
        let mut f = Self {
            root,
            repo,
            base: String::new(),
            candidate: String::new(),
            hash: format!("{:x}", Sha256::digest(NEW.as_bytes())),
        };
        f.git(&["init", "-q"]);
        f.git(&["config", "user.name", "R27 unit fixture"]);
        f.git(&["config", "user.email", "r27@example.test"]);
        fs::write(f.repo.join("compose.yaml"), OLD).unwrap();
        f.git(&["add", "."]);
        f.git(&["commit", "-qm", "baseline"]);
        f.git(&["tag", "v1"]);
        f.base = f.git(&["rev-parse", "HEAD"]);
        fs::write(f.repo.join("compose.yaml"), NEW).unwrap();
        f.git(&["add", "."]);
        f.git(&["commit", "-qm", "candidate"]);
        f.git(&["tag", "v2"]);
        f.candidate = f.git(&["rev-parse", "HEAD"]);
        f
    }
    fn config(&self, checks: Vec<Value>) -> PathBuf {
        let path = self.root.join("request.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema":"tredven.upstream.system-upgrade.v1",
                "project":"postgres-integration",
                "repo":self.repo,
                "baseline_tag":"v1","candidate_tag":"v2",
                "compose_path":"compose.yaml",
                "upgrading_service":"db",
                "checks":checks
            }))
            .unwrap(),
        )
        .unwrap();
        path
    }
    fn run(&self, path: &Path, stage: Option<&Path>) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"));
        cmd.args(["qualify-system", "--config"]).arg(path);
        if let Some(dir) = stage {
            cmd.arg("--stage-dir").arg(dir);
        }
        cmd.output().unwrap()
    }
    fn checks(&self, fail: Option<(&str, &str)>, bad_source: bool) -> Vec<Value> {
        let mut checks = Vec::new();
        let items = [
            ("api", "health"),
            ("api", "integration"),
            ("db", "health"),
            ("db", "integration"),
            ("db", "data-migration"),
            ("db", "rollback"),
            ("worker", "health"),
            ("worker", "integration"),
        ];
        for (service, kind) in items {
            let result = if fail == Some((service, kind)) {
                "failed"
            } else {
                "passed"
            };
            let input = json!({
                "schema":"tredven.upstream.system-test-receipt.v1",
                "candidate_commit":if bad_source && service=="db" && kind=="health" {
                    self.base.as_str()
                } else {self.candidate.as_str()},
                "compose_sha256":self.hash,
                "service":service,"kind":kind,"result":result,
                "tests_passed":if result=="passed" {1} else {0},
                "tests_failed":if result=="failed" {1} else {0},
                "isolated":true
            });
            let file = self.root.join(format!("test-{service}-{kind}.json"));
            let data = serde_json::to_vec(&input).unwrap();
            fs::write(&file, &data).unwrap();
            checks.push(json!({
                "service":service,"kind":kind,
                "artifact":file,
                "sha256":format!("{:x}",Sha256::digest(&data))
            }));
        }
        checks
    }
}
fn read(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|_| {
        panic!(
            "{} stdout {}",
            String::from_utf8_lossy(&o.stderr),
            String::from_utf8_lossy(&o.stdout)
        )
    })
}

#[test]
fn postgres_upstream_change_infers_full_reverse_service_impact_and_requires_migration() {
    let f = Fixture::new();
    let p = f.config(vec![]);
    let stage = f.root.join("should-not-exist");
    let out = f.run(&p, Some(&stage));
    assert_eq!(out.status.code(), Some(1)); // guarded stage refuses incomplete evidence
    assert!(!stage.exists());
    let o = f.run(&p, None);
    assert_eq!(o.status.code(), Some(3));
    let r = read(&o);
    assert_eq!(r["decision"], "UNKNOWN");
    assert_eq!(r["affected_services"], json!(["api", "db", "worker"]));
    assert_eq!(r["total_required_checks"], 8);
    assert_eq!(r["covered_required_checks"], 0);
    assert!(
        r["required_checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["service"] == "db"
                && c["kind"] == "data-migration"
                && c["status"] == "UNKNOWN")
    );
    assert_eq!(r["baseline_image"], "postgres:16");
    assert_eq!(r["candidate_image"], "postgres:17");
    assert_eq!(r["production_compatibility_proven"], false);
    assert_eq!(r["one_click_live_upgrade_authorized"], false);
    assert_eq!(r["performed_provider_mutations"], false);
    assert_eq!(r["performed_test_execution"], false);
    assert_eq!(f.git(&["status", "--porcelain"]), "");
}

#[test]
fn source_bound_test_bundle_all_passes_but_can_only_stage_local_proposal() {
    let f = Fixture::new();
    let p = f.config(f.checks(None, false));
    let stage = f.root.join("proposal");
    let out = f.run(&p, Some(&stage));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = read(&out);
    assert_eq!(r["decision"], "REVIEW");
    assert_eq!(r["covered_required_checks"], 8);
    assert_eq!(r["total_required_checks"], 8);
    assert_eq!(r["local_candidate_stage_ready"], true);
    assert_eq!(
        r["test_evidence_origin"],
        "LOCAL_USER_SUPPLIED_SHA_PINNED_UNATTESTED"
    );
    assert_eq!(r["production_compatibility_proven"], false);
    assert_eq!(r["one_click_live_upgrade_authorized"], false);
    assert_eq!(
        fs::read_to_string(stage.join("candidate.compose.yaml")).unwrap(),
        NEW
    );
    let saved: Value =
        serde_json::from_slice(&fs::read(stage.join("upgrade-review.json")).unwrap()).unwrap();
    assert_eq!(saved["candidate_commit"], f.candidate);
    assert_eq!(saved["candidate_compose_sha256"], f.hash);
    assert_eq!(f.git(&["status", "--porcelain"]), "");
    let retry = f.run(&p, Some(&stage));
    assert_eq!(retry.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&retry.stderr).contains("LOCAL_STAGE_TARGET_ALREADY_EXISTS"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&stage).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(stage.join("candidate.compose.yaml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn failed_integration_test_blocks_staging_even_if_other_checks_are_passed() {
    let f = Fixture::new();
    let p = f.config(f.checks(Some(("api", "integration")), false));
    let stage = f.root.join("must-not-stage");
    let out = f.run(&p, None);
    assert_eq!(out.status.code(), Some(2));
    let r = read(&out);
    assert_eq!(r["decision"], "BLOCKED");
    assert!(
        r["required_checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["service"] == "api"
                && c["kind"] == "integration"
                && c["status"] == "BLOCKED")
    );
    let stage_out = f.run(&p, Some(&stage));
    assert_eq!(stage_out.status.code(), Some(1));
    assert!(!stage.exists());
}

#[test]
fn stale_git_commit_evidence_blocks_even_when_self_report_claims_pass() {
    let f = Fixture::new();
    let p = f.config(f.checks(None, true));
    let o = f.run(&p, None);
    assert_eq!(o.status.code(), Some(2));
    let r = read(&o);
    assert_eq!(r["decision"], "BLOCKED");
    assert!(
        r["required_checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["service"] == "db"
                && c["kind"] == "health"
                && c["reason"] == "TEST_RECEIPT_SOURCE_OR_SCOPE_MISMATCH")
    );
}

#[test]
fn missing_test_artifact_and_invalid_sha_do_not_become_green() {
    let f = Fixture::new();
    let mut checks = f.checks(None, false);
    checks[0]["sha256"] = "0".repeat(64).into();
    let p = f.config(checks);
    let out = f.run(&p, None);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(read(&out)["decision"], "BLOCKED");
}

#[test]
fn unrelated_compose_config_change_never_qualifies_for_one_action_staging() {
    let mut f = Fixture::new();
    let altered = NEW.replace("  worker:\n", "    ports: [\"9999:9999\"]\n  worker:\n");
    fs::write(f.repo.join("compose.yaml"), &altered).unwrap();
    f.git(&["add", "compose.yaml"]);
    f.git(&["commit", "-qm", "unrelated-network-change"]);
    f.git(&["tag", "-f", "v2"]);
    f.candidate = f.git(&["rev-parse", "HEAD"]);
    f.hash = format!("{:x}", Sha256::digest(altered.as_bytes()));
    let p = f.config(f.checks(None, false));
    let stage = f.root.join("must-not-stage");
    let out = f.run(&p, None);
    assert_eq!(out.status.code(), Some(3));
    let r = read(&out);
    assert_eq!(r["decision"], "UNKNOWN");
    assert_eq!(r["reason"], "SYSTEM_CONNECTION_OR_CHANGE_SCOPE_INCOMPLETE");
    assert_eq!(r["local_candidate_stage_ready"], false);
    assert_eq!(f.run(&p, Some(&stage)).status.code(), Some(1));
    assert!(!stage.exists());
}

#[test]
fn potential_external_service_url_is_counted_but_secrets_are_not_printed() {
    let mut f = Fixture::new();
    let altered=NEW.replace("    depends_on: [db]",
        "    depends_on: [db]\n    environment:\n      PAYMENT_API_URL: https://private.example.invalid/secret");
    fs::write(f.repo.join("compose.yaml"), &altered).unwrap();
    f.git(&["add", "compose.yaml"]);
    f.git(&["commit", "-qm", "new-external-api"]);
    f.git(&["tag", "-f", "v2"]);
    f.candidate = f.git(&["rev-parse", "HEAD"]);
    f.hash = format!("{:x}", Sha256::digest(altered.as_bytes()));
    let p = f.config(f.checks(None, false));
    let out = f.run(&p, None);
    assert_eq!(out.status.code(), Some(3));
    let r = read(&out);
    assert_eq!(r["decision"], "UNKNOWN");
    assert_eq!(r["possible_external_connections"], 1);
    assert_eq!(r["connection_coverage"], "PARTIAL_STATIC_COMPOSE_ONLY");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("private.example.invalid"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("/secret"));
}

#[test]
#[cfg(unix)]
fn git_committed_symlink_compose_is_rejected_without_following_link() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let file = f.repo.join("compose.yaml");
    fs::remove_file(&file).unwrap();
    fs::write(f.repo.join("outside.txt"), NEW).unwrap();
    symlink("outside.txt", &file).unwrap();
    f.git(&["add", "."]);
    f.git(&["commit", "-qm", "replaced-by-symlink"]);
    f.git(&["tag", "-f", "v2"]);
    let p = f.config(vec![]);
    let out = f.run(&p, None);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("COMPOSE_FILE_NOT_REGULAR_GIT_BLOB"));
}
