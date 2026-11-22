//! Source-bound Docker Compose service graph; never executes workloads.
use crate::git_source::{git, inspect_local_git};
use serde::{Deserialize, Serialize};
use serde_yaml_rust2::Value as Yaml;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

pub const SCHEMA: &str = "tredven.upstream.system-upgrade.v1";
const TEST_SCHEMA: &str = "tredven.upstream.system-test-receipt.v1";
const MAX_COMPOSE: usize = 256 * 1024;
const MAX_TEST: u64 = 32 * 1024;
const MAX_SERVICES: usize = 80;
const MAX_CHECKS: usize = 500;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub project: String,
    pub repo: PathBuf,
    pub baseline_tag: String,
    pub candidate_tag: String,
    pub compose_path: String,
    pub upgrading_service: String,
    #[serde(default)]
    pub checks: Vec<TestEvidence>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestEvidence {
    pub service: String,
    pub kind: Kind,
    pub artifact: PathBuf,
    pub sha256: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Health,
    Integration,
    DataMigration,
    Rollback,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestReceipt {
    schema: String,
    candidate_commit: String,
    compose_sha256: String,
    service: String,
    kind: Kind,
    result: String,
    tests_passed: u32,
    tests_failed: u32,
    isolated: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub name: String,
    pub image: Option<String>,
    pub depends_on: Vec<String>,
    pub healthcheck_declared: bool,
    pub persistent_storage_declared: bool,
    pub potential_external_connection_count: usize,
}
#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub service: String,
    pub kind: Kind,
    pub status: &'static str,
    pub reason: &'static str,
    pub artifact_sha256: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub project: String,
    pub baseline_commit: String,
    pub candidate_commit: String,
    pub compose_path: String,
    pub baseline_compose_sha256: String,
    pub candidate_compose_sha256: String,
    pub upgrading_service: String,
    pub baseline_image: String,
    pub candidate_image: String,
    pub declared_services: Vec<Node>,
    pub affected_services: Vec<String>,
    pub required_checks: Vec<CheckResult>,
    pub covered_required_checks: usize,
    pub total_required_checks: usize,
    pub possible_external_connections: usize,
    pub connection_coverage: &'static str,
    pub test_evidence_origin: &'static str,
    pub decision: &'static str,
    pub reason: &'static str,
    pub local_candidate_stage_ready: bool,
    pub production_compatibility_proven: bool,
    pub one_click_live_upgrade_authorized: bool,
    pub performed_provider_mutations: bool,
    pub performed_test_execution: bool,
}
pub struct Output {
    pub report: Report,
    candidate_compose: Vec<u8>,
}
fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 80
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn safe_compose_path(name: &str) -> bool {
    let allowed = [
        "compose.yaml",
        "compose.yml",
        "docker-compose.yml",
        "docker-compose.yaml",
    ];
    name.len() <= 240
        && name.split('/').all(|p| safe_id(p) && p != "." && p != "..")
        && name
            .rsplit('/')
            .next()
            .is_some_and(|base| allowed.contains(&base))
}
fn blob(repo: &Path, commit: &str, name: &str) -> Result<Vec<u8>, String> {
    if !safe_compose_path(name) {
        return Err("UNSAFE_OR_UNSUPPORTED_COMPOSE_PATH".into());
    }
    let tree = git(repo, &["ls-tree", "-z", commit, "--", name])?;
    let mut entries = tree.split(|b| *b == 0).filter(|x| !x.is_empty());
    let e = entries.next().ok_or("COMPOSE_FILE_MISSING_IN_GIT_COMMIT")?;
    if entries.next().is_some() || !e.starts_with(b"100644 blob ") {
        return Err("COMPOSE_FILE_NOT_REGULAR_GIT_BLOB".into());
    }
    let n = e
        .iter()
        .position(|b| *b == b'\t')
        .ok_or("COMPOSE_GIT_TREE_INVALID")?;
    if &e[n + 1..] != name.as_bytes() {
        return Err("COMPOSE_GIT_BLOB_PATH_MISMATCH".into());
    }
    let data = git(repo, &["show", &format!("{commit}:{name}")])?;
    if data.is_empty() || data.len() > MAX_COMPOSE {
        return Err("COMPOSE_TOO_LARGE_OR_EMPTY".into());
    }
    Ok(data)
}
fn as_map(v: &Yaml) -> Result<&serde_yaml_rust2::Mapping, String> {
    v.as_mapping().ok_or("COMPOSE_MAPPING_REQUIRED".into())
}
fn get<'a>(m: &'a serde_yaml_rust2::Mapping, key: &str) -> Option<&'a Yaml> {
    m.get(&Yaml::String(key.into()))
}
fn nonempty(v: Option<&Yaml>) -> bool {
    v.is_some_and(|x| !x.is_null() && !x.as_sequence().is_some_and(Vec::is_empty))
}
fn potential_external(v: Option<&Yaml>) -> usize {
    let Some(value) = v else {
        return 0;
    };
    let keys: Vec<&str> = if let Some(m) = value.as_mapping() {
        m.keys().filter_map(Yaml::as_str).collect()
    } else if let Some(a) = value.as_sequence() {
        a.iter()
            .filter_map(Yaml::as_str)
            .map(|s| s.split('=').next().unwrap_or(""))
            .collect()
    } else {
        return 1;
    };
    keys.iter()
        .filter(|s| {
            let n = s.to_ascii_uppercase();
            [
                "URL", "HOST", "DSN", "ENDPOINT", "BROKER", "DATABASE", "REDIS", "POSTGRES",
                "KAFKA", "SMTP", "SUPABASE", "API_KEY",
            ]
            .iter()
            .any(|keyword| n.contains(keyword))
        })
        .count()
}
fn deps(v: Option<&Yaml>) -> Result<Vec<String>, String> {
    let Some(x) = v else {
        return Ok(Vec::new());
    };
    let names: Vec<String> = if let Some(m) = x.as_mapping() {
        m.keys()
            .map(|key| {
                key.as_str()
                    .ok_or("COMPOSE_DEPENDENCY_INVALID")
                    .map(str::to_owned)
            })
            .collect::<Result<_, _>>()?
    } else if let Some(a) = x.as_sequence() {
        a.iter()
            .map(|key| {
                key.as_str()
                    .ok_or("COMPOSE_DEPENDENCY_INVALID")
                    .map(str::to_owned)
            })
            .collect::<Result<_, _>>()?
    } else {
        return Err("COMPOSE_DEPENDENCY_INVALID".into());
    };
    if names.len() > MAX_SERVICES || names.iter().any(|s| !safe_id(s)) {
        return Err("COMPOSE_DEPENDENCY_INVALID".into());
    }
    Ok(names)
}
struct Snapshot {
    services: BTreeMap<String, Node>,
    unknown: bool,
}
fn parse_compose(raw: &[u8]) -> Result<Snapshot, String> {
    let data: Yaml = serde_yaml_rust2::from_slice(raw).map_err(|_| "UNSUPPORTED_COMPOSE_YAML")?;
    let root = as_map(&data)?;
    let table = as_map(get(root, "services").ok_or("COMPOSE_SERVICES_MISSING")?)?;
    if table.is_empty() || table.len() > MAX_SERVICES {
        return Err("COMPOSE_SERVICE_COUNT_OUT_OF_BOUNDS".into());
    }
    let mut nodes = BTreeMap::new();
    let mut unknown = ["include", "extends"]
        .iter()
        .any(|s| get(root, s).is_some());
    for (key, raw) in table {
        let name = key.as_str().ok_or("COMPOSE_SERVICE_NAME_INVALID")?;
        if !safe_id(name) {
            return Err("COMPOSE_SERVICE_NAME_INVALID".into());
        }
        let service = as_map(raw)?;
        let mut relations = deps(get(service, "depends_on"))?;
        if let Some(links) = get(service, "links") {
            let a = links.as_sequence().ok_or("COMPOSE_LINKS_INVALID")?;
            for link in a {
                let s = link.as_str().ok_or("COMPOSE_LINKS_INVALID")?;
                let service_name = s.split(':').next().unwrap_or("");
                if !safe_id(service_name) {
                    return Err("COMPOSE_LINKS_INVALID".into());
                }
                relations.push(service_name.into());
            }
        }
        relations.sort();
        relations.dedup();
        let image = get(service, "image")
            .and_then(Yaml::as_str)
            .map(str::to_owned);
        if image
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 400 || s.contains("${"))
        {
            unknown = true;
        }
        if [
            "extends",
            "build",
            "env_file",
            "network_mode",
            "external_links",
            "secrets",
        ]
        .iter()
        .any(|s| nonempty(get(service, s)))
        {
            unknown = true;
        }
        let external = potential_external(get(service, "environment"))
            + usize::from(nonempty(get(service, "env_file")))
            + usize::from(nonempty(get(service, "external_links")));
        nodes.insert(
            name.into(),
            Node {
                name: name.into(),
                image,
                depends_on: relations,
                healthcheck_declared: nonempty(get(service, "healthcheck")),
                persistent_storage_declared: nonempty(get(service, "volumes")),
                potential_external_connection_count: external,
            },
        );
    }
    for node in nodes.values() {
        if node.depends_on.iter().any(|dep| !nodes.contains_key(dep)) {
            unknown = true;
        }
    }
    Ok(Snapshot {
        services: nodes,
        unknown,
    })
}
// Normalize only the single selected image reference before comparing
// the full Compose documents. Any other change (ports, env, volumes, service
// wiring, new workloads) makes the local one-action staging ineligible.
fn only_target_image_changed(
    baseline: &[u8],
    candidate: &[u8],
    service: &str,
    baseline_image: &str,
) -> Result<bool, String> {
    let old: Yaml =
        serde_yaml_rust2::from_slice(baseline).map_err(|_| "BASE_COMPOSE_YAML_UNQUALIFIED")?;
    let mut new: Yaml = serde_yaml_rust2::from_slice(candidate)
        .map_err(|_| "CANDIDATE_COMPOSE_YAML_UNQUALIFIED")?;
    let root = new
        .as_mapping_mut()
        .ok_or("CANDIDATE_COMPOSE_MAP_REQUIRED")?;
    let services = root
        .get_mut(&Yaml::String("services".into()))
        .and_then(Yaml::as_mapping_mut)
        .ok_or("CANDIDATE_SERVICES_MISSING")?;
    let selected = services
        .get_mut(&Yaml::String(service.into()))
        .and_then(Yaml::as_mapping_mut)
        .ok_or("CANDIDATE_SERVICE_MISSING")?;
    let image = selected
        .get_mut(&Yaml::String("image".into()))
        .ok_or("CANDIDATE_IMAGE_MISSING")?;
    *image = Yaml::String(baseline_image.into());
    Ok(old == new)
}

fn impacted(old: &Snapshot, new: &Snapshot, target: &str) -> Result<Vec<String>, String> {
    if !old.services.contains_key(target) || !new.services.contains_key(target) {
        return Err("UPGRADE_TARGET_NOT_IN_BOTH_COMPOSE_VERSIONS".into());
    }
    let mut queue = VecDeque::from([target.to_owned()]);
    let mut visited = BTreeSet::new();
    while let Some(name) = queue.pop_front() {
        if !visited.insert(name.clone()) {
            continue;
        }
        for graph in [&old.services, &new.services] {
            for (node, service) in graph {
                if service.depends_on.contains(&name) {
                    queue.push_back(node.clone());
                }
            }
        }
    }
    Ok(visited.into_iter().collect())
}
fn check_proof(
    item: &TestEvidence,
    sha: &str,
    compose_hash: &str,
) -> (&'static str, &'static str, Option<String>) {
    if item.sha256.len() != 64 || !item.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return ("BLOCKED", "INVALID_ARTIFACT_PIN", None);
    }
    let Ok(meta) = fs::symlink_metadata(&item.artifact) else {
        return ("UNKNOWN", "TEST_ARTIFACT_UNAVAILABLE", None);
    };
    if !meta.file_type().is_file() || meta.len() > MAX_TEST {
        return ("BLOCKED", "UNSAFE_TEST_ARTIFACT", None);
    }
    let Ok(bytes) = fs::read(&item.artifact) else {
        return ("UNKNOWN", "TEST_ARTIFACT_UNREADABLE", None);
    };
    let hash = digest(&bytes);
    if !hash.eq_ignore_ascii_case(&item.sha256) {
        return ("BLOCKED", "TEST_ARTIFACT_SHA_MISMATCH", Some(hash));
    }
    let Ok(r) = serde_json::from_slice::<TestReceipt>(&bytes) else {
        return ("BLOCKED", "TEST_RECEIPT_INVALID", Some(hash));
    };
    if r.schema != TEST_SCHEMA
        || r.candidate_commit != sha
        || r.compose_sha256 != compose_hash
        || r.service != item.service
        || r.kind != item.kind
    {
        return (
            "BLOCKED",
            "TEST_RECEIPT_SOURCE_OR_SCOPE_MISMATCH",
            Some(hash),
        );
    }
    if r.result == "failed" || r.tests_failed > 0 {
        return ("BLOCKED", "INTEGRATION_TEST_FAILED", Some(hash));
    }
    if r.result != "passed" || r.tests_passed == 0 || !r.isolated {
        return ("UNKNOWN", "TEST_RESULT_OR_ISOLATION_UNKNOWN", Some(hash));
    }
    (
        "PASSED_UNATTESTED",
        "SOURCE_PINNED_UNATTESTED_TEST_EVIDENCE",
        Some(hash),
    )
}
pub fn parse_request(raw: &[u8], base: &Path) -> Result<Request, String> {
    if raw.is_empty() || raw.len() > 128 * 1024 {
        return Err("SYSTEM_REQUEST_TOO_LARGE_OR_EMPTY".into());
    }
    let mut req: Request =
        serde_json::from_slice(raw).map_err(|_| "SYSTEM_REQUEST_INVALID_JSON")?;
    if req.schema != SCHEMA
        || !safe_id(&req.project)
        || !safe_id(&req.upgrading_service)
        || !safe_compose_path(&req.compose_path)
        || req.checks.len() > MAX_CHECKS
    {
        return Err("SYSTEM_REQUEST_INVALID_SCOPE".into());
    }
    let mut pairs = BTreeSet::new();
    for c in &mut req.checks {
        if !safe_id(&c.service) || !pairs.insert((c.service.clone(), c.kind)) {
            return Err("SYSTEM_REQUEST_DUPLICATE_CHECK".into());
        }
        if c.artifact.is_relative() {
            c.artifact = base.join(&c.artifact);
        }
    }
    if req.repo.is_relative() {
        req.repo = base.join(&req.repo);
    }
    Ok(req)
}
pub fn qualify(req: Request) -> Result<Output, String> {
    let source = inspect_local_git(
        &req.repo,
        &req.project,
        &req.baseline_tag,
        &req.candidate_tag,
    )?;
    let baseline_commit = source
        .baseline_commit
        .ok_or("BASELINE_COMMIT_NOT_OBSERVED")?;
    let candidate_commit = source
        .candidate_commit
        .ok_or("CANDIDATE_COMMIT_NOT_OBSERVED")?;
    let before = blob(&req.repo, &baseline_commit, &req.compose_path)?;
    let after = blob(&req.repo, &candidate_commit, &req.compose_path)?;
    let a = parse_compose(&before)?;
    let b = parse_compose(&after)?;
    let impact = impacted(&a, &b, &req.upgrading_service)?;
    let old = a.services[&req.upgrading_service]
        .image
        .clone()
        .ok_or("TARGET_BASE_IMAGE_UNKNOWN")?;
    let new = b.services[&req.upgrading_service]
        .image
        .clone()
        .ok_or("TARGET_CANDIDATE_IMAGE_UNKNOWN")?;
    if old == new || old.contains("${") || new.contains("${") {
        return Err("UPGRADE_TARGET_IMAGE_NOT_EXPLICITLY_CHANGED".into());
    }
    let other_compose_changes =
        !only_target_image_changed(&before, &after, &req.upgrading_service, &old)?;
    let other_images_changed = a
        .services
        .keys()
        .chain(b.services.keys())
        .filter(|id| *id != &req.upgrading_service)
        .any(|id| a.services.get(id).map(|s| &s.image) != b.services.get(id).map(|s| &s.image));
    let image = new.to_ascii_lowercase();
    let stateful = [
        "postgres", "mysql", "mariadb", "mongo", "redis", "rabbitmq", "kafka",
    ]
    .iter()
    .any(|term| image.contains(term))
        || a.services[&req.upgrading_service].persistent_storage_declared
        || b.services[&req.upgrading_service].persistent_storage_declared;
    let mut required = BTreeSet::new();
    for id in &impact {
        required.insert((id.clone(), Kind::Health));
        required.insert((id.clone(), Kind::Integration));
    }
    required.insert((req.upgrading_service.clone(), Kind::Rollback));
    if stateful {
        required.insert((req.upgrading_service.clone(), Kind::DataMigration));
    }
    let hash = digest(&after);
    let mut checks = Vec::new();
    for (service, kind) in required {
        let p = req
            .checks
            .iter()
            .find(|x| x.service == service && x.kind == kind);
        let (status, reason, artifact_sha256) = if let Some(x) = p {
            check_proof(x, &candidate_commit, &hash)
        } else {
            ("UNKNOWN", "REQUIRED_COMPATIBILITY_TEST_MISSING", None)
        };
        checks.push(CheckResult {
            service,
            kind,
            status,
            reason,
            artifact_sha256,
        });
    }
    let unrelated = req.checks.iter().any(|p| {
        !checks
            .iter()
            .any(|c| c.service == p.service && c.kind == p.kind)
    });
    let external: usize = b
        .services
        .values()
        .map(|s| s.potential_external_connection_count)
        .sum();
    let baseline_external: usize = a
        .services
        .values()
        .map(|s| s.potential_external_connection_count)
        .sum();
    let unknown = a.unknown
        || b.unknown
        || external > 0
        || baseline_external > 0
        || other_images_changed
        || other_compose_changes
        || unrelated;
    let blocked = checks.iter().any(|x| x.status == "BLOCKED");
    let complete = checks.iter().all(|x| x.status == "PASSED_UNATTESTED");
    let (decision, reason) = if blocked {
        ("BLOCKED", "COMPATIBILITY_TEST_FAILED_OR_MISMATCHED")
    } else if unknown {
        ("UNKNOWN", "SYSTEM_CONNECTION_OR_CHANGE_SCOPE_INCOMPLETE")
    } else if !complete {
        ("UNKNOWN", "REQUIRED_COMPATIBILITY_EVIDENCE_MISSING")
    } else {
        ("REVIEW", "COMPLETE_SELF_REPORTED_TESTS_LOCAL_STAGING_ONLY")
    };
    let covered = checks
        .iter()
        .filter(|x| x.status == "PASSED_UNATTESTED")
        .count();
    let report = Report {
        schema: SCHEMA,
        project: req.project,
        baseline_commit,
        candidate_commit,
        compose_path: req.compose_path,
        baseline_compose_sha256: digest(&before),
        candidate_compose_sha256: hash,
        upgrading_service: req.upgrading_service,
        baseline_image: old,
        candidate_image: new,
        declared_services: b.services.into_values().collect(),
        affected_services: impact,
        total_required_checks: checks.len(),
        covered_required_checks: covered,
        required_checks: checks,
        possible_external_connections: external,
        connection_coverage: "PARTIAL_STATIC_COMPOSE_ONLY",
        test_evidence_origin: "LOCAL_USER_SUPPLIED_SHA_PINNED_UNATTESTED",
        decision,
        reason,
        local_candidate_stage_ready: decision == "REVIEW",
        production_compatibility_proven: false,
        one_click_live_upgrade_authorized: false,
        performed_provider_mutations: false,
        performed_test_execution: false,
    };
    Ok(Output {
        report,
        candidate_compose: after,
    })
}
impl Output {
    /// Copies a Git-proven candidate snapshot into a new private directory.
    /// This is NOT a live upgrade, deploy, merge, or proof of safe migration.
    pub fn stage_local_candidate(&self, folder: &Path) -> Result<(), String> {
        if !self.report.local_candidate_stage_ready {
            return Err("LOCAL_UPGRADE_STAGING_GATE_NOT_SATISFIED".into());
        }
        if folder.exists() || fs::symlink_metadata(folder).is_ok() {
            return Err("LOCAL_STAGE_TARGET_ALREADY_EXISTS".into());
        }
        let parent = folder.parent().ok_or("LOCAL_STAGE_PARENT_MISSING")?;
        let meta = fs::symlink_metadata(parent).map_err(|_| "LOCAL_STAGE_PARENT_UNAVAILABLE")?;
        if !meta.file_type().is_dir() {
            return Err("LOCAL_STAGE_PARENT_NOT_DIRECTORY".into());
        }
        let name = folder
            .file_name()
            .and_then(|x| x.to_str())
            .ok_or("LOCAL_STAGE_NAME_INVALID")?;
        if !safe_id(name) {
            return Err("LOCAL_STAGE_NAME_INVALID".into());
        }
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(folder)
            .map_err(|_| "LOCAL_STAGE_CREATE_FAILED")?;
        let report = serde_json::to_vec_pretty(&self.report)
            .map_err(|_| "LOCAL_STAGE_SERIALIZATION_FAILED")?;
        for (name, bytes) in [
            ("upgrade-review.json", report.as_slice()),
            ("candidate.compose.yaml", self.candidate_compose.as_slice()),
        ] {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            use std::io::Write;
            options
                .open(folder.join(name))
                .and_then(|mut f| f.write_all(bytes))
                .map_err(|_| "LOCAL_STAGE_WRITE_FAILED")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovers_transitive_runtime_relationships_and_never_exposes_secrets() {
        let data = br#"
services:
  db:
    image: postgres:17
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck: {test: [CMD, pg_isready]}
  api:
    image: example/api:1
    depends_on:
      db: {condition: service_healthy}
    environment:
      DATABASE_URL: "postgres://user:SECRET_PASSWORD@db/app"
      STRIPE_API_KEY: SUPERSECRET
  worker:
    image: example/worker:1
    depends_on: [api]
"#;
        let g = parse_compose(data).unwrap();
        assert_eq!(g.services["api"].depends_on, ["db"]);
        assert_eq!(g.services["api"].potential_external_connection_count, 2);
        assert!(g.services["db"].persistent_storage_declared);
        assert_eq!(impacted(&g, &g, "db").unwrap(), ["api", "db", "worker"]);
        assert!(!format!("{:?}", g.services).contains("SECRET_PASSWORD"));
        assert!(!format!("{:?}", g.services).contains("SUPERSECRET"));
    }
    #[test]
    fn rejects_unknown_topology_and_unsafe_paths() {
        assert!(parse_compose(b"services: []").is_err());
        assert!(parse_compose(b"services: { web: {depends_on: 42} }").is_err());
        let g = parse_compose(b"include: [other.yml]\nservices:\n  web: {image: nginx:1}").unwrap();
        assert!(g.unknown);
        for path in [
            "../compose.yaml",
            "/compose.yaml",
            "x/../compose.yaml",
            "-unsafe/compose.yaml",
            "compose.yaml\n",
            "Dockerfile",
        ] {
            assert!(!safe_compose_path(path), "{path}");
        }
        assert!(safe_compose_path("infra/docker-compose.yaml"));
    }
}
