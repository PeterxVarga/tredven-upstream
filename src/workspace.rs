//! R30 GitHub-backed opt-in workspace; read-only provider calls, no GitHub writes.
//! Reuses the GitHub CLI's existing authentication and the Rust report/policy
//! vocabulary. Never stores credentials or claims tests which were not run.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA: &str = "tredven.upstream.github-workspace.v1";
const MAX_STATE: u64 = 4 * 1024 * 1024;
const MAX_API: usize = 8 * 1024 * 1024;
const MAX_REPOS: usize = 1000;
const MAX_FILES: usize = 120_000;
const GH_HOST: &str = "github.com";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    pub schema: String,
    pub provider: String,
    pub auth_model: String,
    pub account: String,
    pub account_id: u64,
    pub installation_id: Option<u64>,
    pub synced_unix: u64,
    pub repository_coverage: String,
    pub repositories: Vec<Repository>,
    pub provider_writes_authorized: bool,
    pub automated_upgrade_authorized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub id: u64,
    pub full_name: String,
    pub html_url: String,
    pub private: bool,
    pub archived: bool,
    pub disabled: bool,
    pub fork: bool,
    pub language: Option<String>,
    pub default_branch: String,
    pub pushed_at: Option<String>,
    pub selected: bool,
    pub recommendation: String,
    pub review: Option<MaintenanceReview>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceReview {
    pub schema: String,
    pub repository_id: u64,
    pub source_commit: String,
    pub source_tree: String,
    pub manifest_paths: Vec<String>,
    pub tech_signals: Vec<String>,
    pub service_connections: Vec<String>,
    pub ci_paths: Vec<String>,
    pub open_upgrade_prs: Vec<UpgradePr>,
    pub explicit_pr: Option<UpgradePr>,
    #[serde(default)]
    pub pr_source_impact: Option<crate::PreflightReport>,
    #[serde(default)]
    pub system_gate: Option<BoundSystemGate>,
    pub tree_complete: bool,
    pub pull_list_complete: bool,
    pub decision: String,
    pub reasons: Vec<String>,
    pub evidence_origin: String,
    pub integration_e2e_proven: bool,
    pub r29_system_upgrade_gate: String,
    pub live_upgrade_authorized: bool,
}

/// The existing R27/R29 Rust compatibility gate, bound to an exact GitHub PR.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundSystemGate {
    pub decision: String,
    pub baseline_commit: String,
    pub candidate_commit: String,
    pub affected_services: Vec<String>,
    pub covered_checks: usize,
    pub required_checks: usize,
    pub test_evidence_origin: String,
    pub source_bound_to_selected_pr: bool,
    pub actual_test_execution_by_this_command: bool,
    pub live_upgrade_authorized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradePr {
    pub number: u64,
    pub title: String,
    pub html_url: String,
    pub head_sha: String,
    pub base_sha: String,
    pub author: String,
    pub draft: bool,
    pub kind: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |x| x.as_secs())
}
fn safe_name(s: &str) -> bool {
    (1..=100).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        && !s.starts_with('-')
        && s != "."
        && s != ".."
}
fn safe_full_name(s: &str) -> bool {
    let mut parts = s.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(owner), Some(repo), None) => safe_name(owner) && safe_name(repo),
        _ => false,
    }
}
fn sha40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|c| c.is_ascii_hexdigit())
}
fn value_str<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("GITHUB_MISSING_{key}"))
}
fn value_u64(v: &serde_json::Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("GITHUB_MISSING_{key}"))
}
fn value_bool(v: &serde_json::Value, key: &str) -> Result<bool, String> {
    v.get(key)
        .and_then(|v| v.as_bool())
        .ok_or_else(|| format!("GITHUB_MISSING_{key}"))
}
fn bound_gh(exe: &str, endpoint: &str) -> Result<serde_json::Value, String> {
    // No shell, token, arbitrary URL, or provider writes. gh uses a user's
    // independently managed login (keyring, GitHub CLI). gh prompts disabled.
    if exe.is_empty()
        || endpoint.len() > 350
        || !endpoint.is_ascii()
        || endpoint.starts_with('/')
        || endpoint.contains("://")
        // Allow only the official GitHub BASE...HEAD compare separator.
        || endpoint.replace("...", "").contains("..")
        || endpoint
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b == b'#')
    {
        return Err("GH_PROVIDER_ENDPOINT_NOT_ALLOWED".into());
    }
    let output = Command::new(exe)
        .args([
            "api",
            "--hostname",
            GH_HOST,
            "-X",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            endpoint,
        ])
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_HTTP_TIMEOUT", "15")
        .output()
        .map_err(|_| "GITHUB_CLI_NOT_AVAILABLE")?;
    if !output.status.success() {
        // Avoid leaking private GitHub/API output or auth details.
        return Err("GITHUB_READ_ONLY_REQUEST_DENIED_OR_UNAVAILABLE".into());
    }
    if output.stdout.is_empty() || output.stdout.len() > MAX_API {
        return Err("GITHUB_API_RESPONSE_OUT_OF_BOUNDS".into());
    }
    serde_json::from_slice(&output.stdout).map_err(|_| "GITHUB_RESPONSE_NOT_JSON".into())
}
fn github_account(gh: &str) -> Result<(u64, String), String> {
    let v = bound_gh(gh, "user")?;
    let id = value_u64(&v, "id")?;
    let name = value_str(&v, "login")?;
    if id == 0 || !safe_name(name) {
        return Err("GITHUB_ACCOUNT_INVALID".into());
    }
    Ok((id, name.into()))
}
fn github_repo(
    v: &serde_json::Value,
    old_selected: bool,
    old_review: Option<MaintenanceReview>,
) -> Result<Repository, String> {
    let id = value_u64(v, "id")?;
    let full_name = value_str(v, "full_name")?.to_owned();
    let branch = value_str(v, "default_branch")?.to_owned();
    if id == 0 || !safe_full_name(&full_name) || branch.is_empty() || branch.len() > 150 {
        return Err("GITHUB_REPO_IDENTITY_INVALID".into());
    }
    let private = value_bool(v, "private")?;
    let archived = value_bool(v, "archived")?;
    let disabled = value_bool(v, "disabled")?;
    let fork = value_bool(v, "fork")?;
    let pushed_at = v
        .get("pushed_at")
        .and_then(|x| x.as_str())
        .map(str::to_owned);
    let lang = v
        .get("language")
        .and_then(|x| x.as_str())
        .map(str::to_owned);
    let url = value_str(v, "html_url")?.to_owned();
    if url != format!("https://github.com/{full_name}") {
        return Err("GITHUB_REPO_LINK_IDENTITY_MISMATCH".into());
    }
    let recommendation = if archived || disabled {
        "ARCHIVED_OR_DISABLED"
    } else if fork {
        "FORK_REQUIRES_REVIEW"
    } else if lang.is_some() {
        "LIKELY_ACTIVE_SOURCE"
    } else {
        "UNCLASSIFIED"
    };
    Ok(Repository {
        id,
        full_name,
        html_url: url,
        private,
        archived,
        disabled,
        fork,
        language: lang,
        default_branch: branch,
        pushed_at,
        selected: old_selected,
        recommendation: recommendation.into(),
        review: old_review,
    })
}
pub fn sync(state_path: &Path, gh: &str) -> Result<Workspace, String> {
    let (account_id, account) = github_account(gh)?;
    let previous = if state_path.exists() {
        Some(load(state_path)?)
    } else {
        None
    };
    if previous
        .as_ref()
        .is_some_and(|s| s.account_id != account_id)
    {
        return Err("WORKSPACE_ACCOUNT_CHANGED_REFUSE_CROSS_ACCOUNT_SYNC".into());
    }
    let mut repositories = Vec::new();
    let mut ids = BTreeSet::new();
    let mut complete = false;
    for page in 1..=11 {
        let endpoint = format!(
            "user/repos?per_page=100&page={page}&sort=pushed&direction=desc&affiliation=owner,collaborator,organization_member"
        );
        let v = bound_gh(gh, &endpoint)?;
        let raw = v.as_array().ok_or("GITHUB_REPOSITORIES_NOT_ARRAY")?;
        if raw.len() > 100 {
            return Err("GITHUB_REPOSITORY_PAGE_TOO_LARGE".into());
        }
        for item in raw {
            let id = value_u64(item, "id")?;
            if !ids.insert(id) {
                return Err("GITHUB_DUPLICATE_REPOSITORY_ID".into());
            }
            let prior = previous
                .as_ref()
                .and_then(|s| s.repositories.iter().find(|r| r.id == id));
            let old_selected = prior.is_some_and(|r| r.selected);
            let old_review = prior.and_then(|r| r.review.clone());
            let mut repo = github_repo(item, old_selected, old_review)?;
            // Source state is invalidated if repository default branch changes
            // or if its latest pushed timestamp differs.
            if prior.is_some_and(|r| {
                r.default_branch != repo.default_branch || r.pushed_at != repo.pushed_at
            }) {
                repo.review = None;
            }
            repositories.push(repo);
            if repositories.len() > MAX_REPOS {
                return Err("GITHUB_REPOSITORY_SCOPE_EXCEEDED".into());
            }
        }
        if raw.len() < 100 {
            complete = true;
            break;
        }
    }
    if !complete {
        // Missing data is not zero: do not overwrite a previous complete state.
        return Err("GITHUB_REPOSITORY_PAGINATION_INCOMPLETE".into());
    }
    let state = Workspace {
        schema: SCHEMA.into(),
        provider: "github".into(),
        auth_model: "EXISTING_GITHUB_CLI_USER_SESSION".into(),
        account,
        account_id,
        installation_id: None,
        synced_unix: now(),
        repository_coverage: "COMPLETE_API_PAGINATION_WITHIN_1000".into(),
        repositories,
        provider_writes_authorized: false,
        automated_upgrade_authorized: false,
    };
    save(state_path, &state)?;
    Ok(state)
}

fn check_store_path(path: &Path, creating: bool) -> Result<(), String> {
    let parent = path.parent().ok_or("WORKSPACE_PARENT_REQUIRED")?;
    let meta = fs::symlink_metadata(parent).map_err(|_| "WORKSPACE_PARENT_MUST_EXIST_PRIVATE")?;
    if !meta.file_type().is_dir() {
        return Err("WORKSPACE_PARENT_NOT_REAL_DIRECTORY".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("WORKSPACE_DIRECTORY_MUST_BE_PRIVATE_0700".into());
        }
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.file_type().is_file() {
            return Err("WORKSPACE_FILE_NOT_REGULAR".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err("WORKSPACE_FILE_MUST_BE_PRIVATE_0600".into());
            }
        }
    } else if !creating {
        return Err("WORKSPACE_STATE_MISSING".into());
    }
    Ok(())
}
fn validate(state: &Workspace) -> Result<(), String> {
    if state.schema != SCHEMA
        || state.provider != "github"
        || state.auth_model != "EXISTING_GITHUB_CLI_USER_SESSION"
        || state.account_id == 0
        || !safe_name(&state.account)
        || state.installation_id.is_some()
        || state.provider_writes_authorized
        || state.automated_upgrade_authorized
        || state.repository_coverage != "COMPLETE_API_PAGINATION_WITHIN_1000"
        || state.repositories.len() > MAX_REPOS
    {
        return Err("WORKSPACE_STATE_INVALID_OR_UNSAFE".into());
    }
    let mut names = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for r in &state.repositories {
        if r.id == 0
            || !ids.insert(r.id)
            || !names.insert(&r.full_name)
            || !safe_full_name(&r.full_name)
            || r.html_url != format!("https://github.com/{}", r.full_name)
        {
            return Err("WORKSPACE_REPO_RECORD_NOT_UNIQUE_OR_VALID".into());
        }
        if let Some(report) = &r.review {
            if !r.selected
                || report.repository_id != r.id
                || !sha40(&report.source_commit)
                || report.live_upgrade_authorized
                || report.integration_e2e_proven
            {
                return Err("WORKSPACE_REVIEW_CANNOT_AUTHORIZE_LIVE_UPGRADE".into());
            }
            if let Some(gate) = &report.system_gate {
                let pr = report
                    .explicit_pr
                    .as_ref()
                    .ok_or("WORKSPACE_SYSTEM_GATE_REQUIRES_EXPLICIT_PR")?;
                if !gate.source_bound_to_selected_pr
                    || gate.live_upgrade_authorized
                    || gate.actual_test_execution_by_this_command
                    || gate.baseline_commit != pr.base_sha
                    || gate.candidate_commit != pr.head_sha
                    || gate.decision != report.r29_system_upgrade_gate
                    || !matches!(gate.decision.as_str(), "BLOCKED" | "UNKNOWN" | "REVIEW")
                    || (gate.decision == "BLOCKED" && report.decision != "BLOCKED")
                    || (gate.decision != "BLOCKED" && report.decision != "UNKNOWN")
                {
                    return Err("WORKSPACE_R29_GATE_CANNOT_FORGE_PR_OR_LIVE_AUTHORITY".into());
                }
            }
        }
    }
    Ok(())
}
pub fn load(path: &Path) -> Result<Workspace, String> {
    check_store_path(path, false)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| "WORKSPACE_FILE_NOT_FOUND")?;
    if metadata.len() == 0 || metadata.len() > MAX_STATE {
        return Err("WORKSPACE_FILE_SIZE_INVALID".into());
    }
    let bytes = fs::read(path).map_err(|_| "WORKSPACE_FILE_READ_FAILED")?;
    let state: Workspace = serde_json::from_slice(&bytes).map_err(|_| "WORKSPACE_INVALID_JSON")?;
    validate(&state)?;
    Ok(state)
}
pub fn save(path: &Path, state: &Workspace) -> Result<(), String> {
    validate(state)?;
    check_store_path(path, true)?;
    let bytes = serde_json::to_vec_pretty(state).map_err(|_| "WORKSPACE_SERIALIZE_FAILED")?;
    if bytes.len() as u64 > MAX_STATE {
        return Err("WORKSPACE_TOO_LARGE".into());
    }
    let tmp = path.with_file_name(format!(
        ".{}.r30-{}-{}.tmp",
        path.file_name()
            .and_then(|x| x.to_str())
            .ok_or("WORKSPACE_FILE_NAME_REQUIRED")?,
        std::process::id(),
        now()
    ));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|_| "WORKSPACE_TEMP_CREATE_DENIED")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "WORKSPACE_PERMISSIONS_FAILED")?;
    }
    let result = (|| -> Result<(), String> {
        f.write_all(&bytes).map_err(|_| "WORKSPACE_WRITE_FAILED")?;
        f.sync_all().map_err(|_| "WORKSPACE_SYNC_FAILED")?;
        fs::rename(&tmp, path).map_err(|_| "WORKSPACE_ATOMIC_REPLACE_FAILED")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
pub fn set_selected(path: &Path, repository_id: u64, selected: bool) -> Result<Workspace, String> {
    let mut state = load(path)?;
    let r = state
        .repositories
        .iter_mut()
        .find(|r| r.id == repository_id)
        .ok_or("REPOSITORY_NOT_IN_AUTHENTICATED_INVENTORY")?;
    if (r.archived || r.disabled) && selected {
        return Err("ARCHIVED_OR_DISABLED_REPO_NOT_MONITORABLE".into());
    }
    r.selected = selected;
    if !selected {
        r.review = None;
    }
    save(path, &state)?;
    Ok(state)
}

fn encode_ref(s: &str) -> String {
    let mut result = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            result.push(b as char);
        } else {
            result.push_str(&format!("%{b:02X}"));
        }
    }
    result
}
fn tech(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    match name.as_str() {
        "cargo.toml" | "cargo.lock" => Some("Rust/Cargo"),
        "go.mod" | "go.sum" => Some("Go Modules"),
        "package.json" | "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock" => Some("Node.js"),
        "pyproject.toml" | "uv.lock" | "poetry.lock" | "requirements.txt" | "pipfile.lock" => {
            Some("Python")
        }
        "gemfile" | "gemfile.lock" => Some("Ruby"),
        "pom.xml" | "build.gradle" | "build.gradle.kts" => Some("JVM"),
        "composer.json" | "composer.lock" => Some("PHP/Composer"),
        "dockerfile" => Some("Container"),
        "compose.yaml" | "compose.yml" | "docker-compose.yml" | "docker-compose.yaml" => {
            Some("Compose")
        }
        _ => None,
    }
}
fn interesting(path: &str) -> bool {
    tech(path).is_some()
        || path.starts_with(".github/workflows/")
            && (path.ends_with(".yml") || path.ends_with(".yaml"))
}
fn is_compose(path: &str) -> bool {
    matches!(
        path.rsplit('/').next().unwrap_or(path),
        "compose.yaml" | "compose.yml" | "docker-compose.yml" | "docker-compose.yaml"
    )
}
fn pull(v: &serde_json::Value) -> Result<UpgradePr, String> {
    let number = value_u64(v, "number")?;
    let user = v
        .get("user")
        .and_then(|u| u.get("login"))
        .and_then(|v| v.as_str())
        .ok_or("GITHUB_PULL_AUTHOR_MISSING")?;
    let title = value_str(v, "title")?;
    let base = v
        .get("base")
        .and_then(|v| v.get("sha"))
        .and_then(|v| v.as_str())
        .ok_or("GITHUB_PULL_BASE_MISSING")?;
    let head = v
        .get("head")
        .and_then(|v| v.get("sha"))
        .and_then(|v| v.as_str())
        .ok_or("GITHUB_PULL_HEAD_MISSING")?;
    if !sha40(base) || !sha40(head) {
        return Err("GITHUB_PULL_COMMIT_INVALID".into());
    }
    let login = user.to_ascii_lowercase();
    let kind = if login.contains("dependabot") || login.contains("renovate") {
        "DEPENDENCY_BOT"
    } else if title.to_ascii_lowercase().contains("upgrade")
        || title.to_ascii_lowercase().contains("bump ")
        || title.to_ascii_lowercase().contains("update ")
    {
        "POSSIBLE_UPGRADE"
    } else {
        "OTHER"
    };
    Ok(UpgradePr {
        number,
        title: title.chars().take(230).collect(),
        html_url: value_str(v, "html_url")?.into(),
        head_sha: head.into(),
        base_sha: base.into(),
        author: user.into(),
        draft: value_bool(v, "draft")?,
        kind: kind.into(),
    })
}
pub fn review(
    path: &Path,
    repository_id: u64,
    gh: &str,
    pr_number: Option<u64>,
) -> Result<Workspace, String> {
    let mut state = load(path)?;
    let (account_id, _) = github_account(gh)?;
    if state.account_id != account_id {
        return Err("WORKSPACE_ACCOUNT_CHANGED".into());
    }
    let idx = state
        .repositories
        .iter()
        .position(|r| r.id == repository_id && r.selected)
        .ok_or("REPOSITORY_MUST_BE_SELECTED")?;
    let r = &state.repositories[idx];
    let name = r.full_name.clone();
    // Require current authenticated access and unchanged repository identity.
    // A removed private repository is never silently treated as an empty repo.
    let current = bound_gh(gh, &format!("repos/{name}"))?;
    if value_u64(&current, "id")? != repository_id {
        return Err("REPOSITORY_ACCESS_OR_IDENTITY_CHANGED".into());
    }
    let branch = value_str(&current, "default_branch")?.to_owned();
    if branch != r.default_branch {
        return Err("REPOSITORY_DEFAULT_BRANCH_CHANGED_RESYNC".into());
    }
    let commit = bound_gh(gh, &format!("repos/{name}/commits/{}", encode_ref(&branch)))?;
    let sha = value_str(&commit, "sha")?;
    if !sha40(sha) {
        return Err("GITHUB_SOURCE_COMMIT_INVALID".into());
    }
    let tree_sha = commit
        .get("commit")
        .and_then(|v| v.get("tree"))
        .and_then(|v| v.get("sha"))
        .and_then(|v| v.as_str())
        .ok_or("GITHUB_SOURCE_TREE_MISSING")?;
    if !sha40(tree_sha) {
        return Err("GITHUB_SOURCE_TREE_INVALID".into());
    }
    let tree = bound_gh(
        gh,
        &format!("repos/{name}/git/trees/{tree_sha}?recursive=1"),
    )?;
    let files = tree
        .get("tree")
        .and_then(|v| v.as_array())
        .ok_or("GITHUB_SOURCE_TREE_MISSING")?;
    if files.len() > MAX_FILES {
        return Err("GITHUB_SOURCE_TREE_TOO_LARGE".into());
    }
    let complete = tree.get("truncated").and_then(|v| v.as_bool()) == Some(false);
    let mut manifest_paths = Vec::new();
    let mut ci_paths = Vec::new();
    let mut technologies = BTreeSet::new();
    let mut connections = BTreeSet::new();
    for item in files {
        if item.get("type").and_then(|v| v.as_str()) != Some("blob") {
            continue;
        }
        let Some(file) = item.get("path").and_then(|v| v.as_str()) else {
            continue;
        };
        if file.len() > 350 {
            continue;
        }
        if interesting(file) {
            if manifest_paths.len() + ci_paths.len() >= 80 {
                continue;
            }
            if file.starts_with(".github/workflows/") {
                ci_paths.push(file.to_owned());
            } else {
                if let Some(t) = tech(file) {
                    technologies.insert(t.into());
                }
                if is_compose(file) {
                    connections.insert("COMPOSE_PRESENT_CONNECTIONS_NOT_YET_VERIFIED".to_owned());
                }
                manifest_paths.push(file.into());
            }
        }
    }
    // Read-only PR snapshot: a full 100 entry page is NOT treated as complete.
    let list = bound_gh(
        gh,
        &format!("repos/{name}/pulls?state=open&per_page=100&page=1"),
    )?;
    let all = list.as_array().ok_or("GITHUB_PRS_NOT_ARRAY")?;
    if all.len() > 100 {
        return Err("GITHUB_PULL_SCOPE_UNEXPECTED".into());
    }
    let pulls_complete = all.len() < 100;
    let mut upgrade_prs = Vec::new();
    for v in all {
        let p = pull(v)?;
        if p.html_url != format!("https://github.com/{name}/pull/{}", p.number) {
            return Err("GITHUB_PR_HTML_URL_IDENTITY_MISMATCH".into());
        }
        if p.kind != "OTHER" {
            upgrade_prs.push(p);
        }
    }
    let explicit_pr = if let Some(n) = pr_number {
        if n == 0 || n > 999_999_999 {
            return Err("INVALID_EXPLICIT_PR_NUMBER".into());
        }
        let response = bound_gh(gh, &format!("repos/{name}/pulls/{n}"))?;
        let pr = pull(&response)?;
        if pr.number != n {
            return Err("PR_NUMBER_MISMATCH".into());
        }
        if pr.html_url != format!("https://github.com/{name}/pull/{n}") {
            return Err("GITHUB_PR_HTML_URL_IDENTITY_MISMATCH".into());
        }
        Some(pr)
    } else {
        None
    };
    let pr_source_impact = if let Some(pr) = explicit_pr.as_ref() {
        // Use GitHub's exact PR base/head commits and changed files; delegate
        // classification to the EXISTING Rust preflight core. Do not claim
        // signed origin or passing runtime tests.
        let comparison = bound_gh(
            gh,
            &format!("repos/{name}/compare/{}...{}", pr.base_sha, pr.head_sha),
        )?;
        let changed = comparison
            .get("files")
            .and_then(|v| v.as_array())
            .ok_or("GITHUB_PR_COMPARISON_FILES_UNAVAILABLE")?;
        if changed.len() > 300 {
            return Err("GITHUB_COMPARE_PATHS_OUT_OF_BOUNDS".into());
        }
        let paths = changed
            .iter()
            .map(|f| value_str(f, "filename").map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        let coverage = if changed.len() < 300
            && comparison
                .get("total_commits")
                .and_then(|v| v.as_u64())
                .is_some_and(|count| count <= 250)
            && comparison
                .get("status")
                .and_then(|v| v.as_str())
                .is_some_and(|status| status != "diverged")
        {
            crate::CompareCoverage::Complete
        } else {
            crate::CompareCoverage::Truncated
        };
        let request = crate::PreflightInput {
            schema: crate::INPUT_SCHEMA.into(),
            project: format!("github-{repository_id}"),
            baseline: crate::Release {
                tag: format!("pr-{}-base", pr.number),
                commit: Some(pr.base_sha.clone()),
            },
            candidate: crate::Release {
                tag: format!("pr-{}-head", pr.number),
                commit: Some(pr.head_sha.clone()),
            },
            source_verified: None,
            compare_coverage: coverage,
            changed_paths: paths,
            checks: vec![
                crate::Check {
                    name: "integration_e2e".into(),
                    status: crate::CheckStatus::Unknown,
                },
                crate::Check {
                    name: "rollback_safety".into(),
                    status: crate::CheckStatus::Unknown,
                },
            ],
        };
        Some(crate::inspect(request)?)
    } else {
        None
    };
    let mut reasons = vec!["INTEGRATION_AND_ROLLBACK_E2E_NOT_RUN_FOR_THIS_REPOSITORY".to_owned()];
    if pr_source_impact.is_some() {
        reasons
            .push("SOURCE_IMPACT_FROM_EXISTING_RUST_PREFLIGHT_NO_SIGNED_RUNTIME_EVIDENCE".into());
    }
    if !complete {
        reasons.push("GITHUB_TREE_TRUNCATED_SCOPE_UNKNOWN".into());
    }
    if !pulls_complete {
        reasons.push("GITHUB_PULL_LIST_TRUNCATED_SCOPE_UNKNOWN".into());
    }
    if manifest_paths.is_empty() {
        reasons.push("NO_SUPPORTED_PROJECT_MANIFEST_OBSERVED".into());
    }
    if explicit_pr.is_none() && upgrade_prs.is_empty() {
        reasons.push("NO_UPGRADE_PR_OBSERVED_NOT_PROOF_NONE_EXIST".into());
    }
    state.repositories[idx].review = Some(MaintenanceReview {
        schema: "tredven.upstream.github-maintenance-review.v1".into(),
        repository_id,
        source_commit: sha.into(),
        source_tree: tree_sha.into(),
        manifest_paths,
        tech_signals: technologies.into_iter().collect(),
        service_connections: connections.into_iter().collect(),
        ci_paths,
        open_upgrade_prs: upgrade_prs,
        explicit_pr,
        pr_source_impact,
        system_gate: None,
        tree_complete: complete,
        pull_list_complete: pulls_complete,
        decision: "UNKNOWN".into(),
        reasons,
        evidence_origin: "AUTHENTICATED_GITHUB_REST_METADATA_NOT_RUNTIME_ATTESTATION".into(),
        integration_e2e_proven: false,
        r29_system_upgrade_gate: "NOT_RUN_NO_REPOSITORY_BOUND_INTEGRATION_RECEIPTS".into(),
        live_upgrade_authorized: false,
    });
    save(path, &state)?;
    Ok(state)
}

// The dashboard renders the exact same private workspace snapshot as the CLI.
// It is deliberately local-only: no public website, backend, cookies or token
// storage, and no imported stylesheet, analytics, or external network requests.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
pub fn dashboard_html(state: &Workspace, session: &str) -> String {
    let mut cards = String::new();
    for r in &state.repositories {
        let selected = if r.selected {
            "Kijelölve"
        } else {
            "Nincs kijelölve"
        };
        let review = r.review.as_ref();
        let decision = review.map_or("NINCS VIZSGÁLAT", |r| r.decision.as_str());
        let language = r.language.as_deref().unwrap_or("Ismeretlen");
        let private = if r.private { "Privát" } else { "Nyilvános" };
        let suggested = html_escape(&r.recommendation);
        let manifest = review.map_or(0, |r| r.manifest_paths.len());
        let pr_count = review.map_or(0, |r| r.open_upgrade_prs.len());
        let impact_count = review
            .and_then(|r| r.pr_source_impact.as_ref())
            .map_or(0, |r| r.changed_paths_considered);
        let sha = review.map_or("—", |r| r.source_commit.as_str());
        let checked = if r.selected { "true" } else { "false" };
        let disabled = if r.archived || r.disabled {
            "disabled"
        } else {
            ""
        };
        let actions = format!(
            "<button data-action='select' data-id='{id}' data-selected='{checked}' {disabled}>{text}</button>",
            id = r.id,
            text = if r.selected {
                "Kijelölés visszavonása"
            } else {
                "Projekt kiválasztása"
            }
        );
        let scan = if r.selected {
            format!(
                "<button class='outline' data-action='review' data-id='{}'>Read-only vizsgálat</button>",
                r.id
            )
        } else {
            String::new()
        };
        let pr_links = review.map_or_else(String::new,|rev|{
            let items=rev.open_upgrade_prs.iter().take(5).map(|p|{
                let action=if r.selected {
                    format!("<button class='outline' data-action='pr' data-id='{}' data-pr='{}'>PR-hatásvizsgálat</button>",
                            r.id,p.number)
                }else{String::new()};
                format!("<div class='pr'><a href='{}' rel='noreferrer' target='_blank'>#{}</a> — {} {}</div>",
                        html_escape(&p.html_url),p.number,html_escape(&p.title),action)
            }).collect::<Vec<_>>().join("");
            if items.is_empty() {String::new()}else{format!("<div class='prs'>{items}</div>")}
        });
        let impact = review.and_then(|r|r.pr_source_impact.as_ref()).map_or_else(String::new,|p|{
            let items=p.impact_candidates.iter().take(5).map(|c|
                format!("<li>{}: {}</li>",html_escape(&c.category),html_escape(&c.path))
            ).collect::<Vec<_>>().join("");
            format!("<p class='small'>Rust hatásosztályok · {} változott fájl · döntés: UNKNOWN</p><ul class='small'>{items}</ul>",
                    p.changed_paths_considered)
        });
        let reasons = review.map_or_else(String::new, |rev| {
            let list = rev
                .reasons
                .iter()
                .map(|s| html_escape(s))
                .collect::<Vec<_>>()
                .join("; ");
            format!("<p class='small'>Bizonyítékhiány: {list}</p>")
        });
        cards.push_str(&format!(
            "<article><div class='top'><div><h2><a href='{url}' rel='noreferrer' target='_blank'>{name}</a></h2><p class='small'>{private} · {lang} · {suggested}</p></div><strong>{decision}</strong></div><p>Kijelölés: {selected} · Manifesztek: {manifest} · Felismert frissítési PR-ek: {pr_count} · Rust PR-hatásvizsgálat: {impact_count} fájl</p><p class='small'>Vizsgált commit: {sha}</p>{pr_links}{impact}{reasons}<div class='actions'>{actions}{scan}</div></article>",
            url=html_escape(&r.html_url),name=html_escape(&r.full_name),
            lang=html_escape(language),decision=html_escape(decision),
            sha=html_escape(sha), reasons=reasons
        ));
    }
    let selected = state.repositories.iter().filter(|r| r.selected).count();
    let reviewed = state
        .repositories
        .iter()
        .filter(|r| r.review.is_some())
        .count();
    let account = html_escape(&state.account);
    let nonce = session;
    format!(
        r#"<!doctype html><html lang="hu"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Tredven · Project Workspace</title><style>
:root{{color-scheme:light dark;font-family:system-ui,-apple-system,sans-serif}}
body{{max-width:1080px;margin:0 auto;padding:40px 24px;background:#f6f6f2;color:#191919}}
header{{display:flex;justify-content:space-between;align-items:end;gap:16px;flex-wrap:wrap;border-bottom:1px solid #ccc;padding-bottom:20px;margin-bottom:24px}}
h1{{font-size:clamp(26px,4vw,42px);margin:0;letter-spacing:-.045em}}
h2{{font-size:18px;margin:0 0 8px;overflow-wrap:anywhere}}
h2 a{{color:inherit;text-decoration:none}}h2 a:hover{{text-decoration:underline}}
.eyebrow{{letter-spacing:.14em;text-transform:uppercase;font-size:11px;font-weight:700}}
.small{{font-size:12px;color:#5c5c5b;line-height:1.6;overflow-wrap:anywhere}}
.stats{{display:flex;gap:24px;align-items:center;flex-wrap:wrap}}
strong{{font-size:11px;letter-spacing:.08em;white-space:nowrap}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:14px}}
article{{background:#fff;border:1px solid #e5e5e2;padding:22px;border-radius:9px;box-shadow:0 1px 4px #00000008}}
article .top{{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}}
article p{{font-size:13px}}.actions{{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}}
button{{background:#1f2720;color:white;border:1px solid #1f2720;border-radius:5px;padding:10px 12px;font:inherit;font-size:12px;cursor:pointer}}
button.outline{{background:transparent;color:#1f2720}}button:disabled{{cursor:not-allowed;opacity:.45}}
.notice{{padding:13px 16px;border:1px solid #dadada;border-radius:5px;font-size:13px;margin-bottom:24px}}
.prs{{border-top:1px solid #ddd;padding-top:12px;margin-top:15px}}.pr{{font-size:12px;margin-bottom:9px;line-height:1.6}}.pr button{{padding:5px 8px;margin-left:6px}}
#feedback{{min-height:18px;font-size:13px}}
@media(prefers-color-scheme:dark){{body{{background:#111;color:#eee}}article{{background:#1c1c1c;border-color:#333}}.small{{color:#b7b7b7}}button.outline{{color:#eee;border-color:#bbb}}.notice{{border-color:#444}}}}
</style></head><body><header><div><div class="eyebrow">TREDVEN / LOCAL WORKSPACE</div><h1>Project inventory.</h1><p class="small">GitHub-fiók: {account} · Read-only, helyi fejlesztői nézet</p></div><div class="stats"><span><strong>{total}</strong> repository</span><span><strong>{selected}</strong> kijelölve</span><span><strong>{reviewed}</strong> vizsgálva</span></div></header><div class="notice">A projektkijelölés nem indít háttérmonitorozást. A vizsgálat csak GitHub-metaadatokat olvas; a kompatibilitási E2E nem fut automatikusan. Bizonyíték nélkül az eredmény UNKNOWN. GitHub App és éles frissítés még nem aktív.</div><p id="feedback" role="status"></p><main class="grid">{cards}</main>
<script nonce="{nonce}">
const session="{nonce}";const status=document.getElementById("feedback");
for(const btn of document.querySelectorAll("button[data-action]")){{
 btn.addEventListener("click",async()=>{{
  const action=btn.dataset.action,repo_id=Number(btn.dataset.id);
  const payload=action==="select"?{{repo_id,selected:btn.dataset.selected!=="true"}}:action==="pr"?{{repo_id,pr_number:Number(btn.dataset.pr)}}:{{repo_id}};
  btn.disabled=true;status.textContent="Read-only kérés...";
  try{{const result=await fetch(action==="select"?"/select":"/review",{{method:"POST",headers:{{"Content-Type":"application/json","X-R30-Session":session}},body:JSON.stringify(payload),credentials:"omit"}});const answer=await result.json();if(!result.ok){{throw Error(answer.error||"UNKNOWN")}}location.reload()}}
  catch(e){{status.textContent="Elutasítva: "+String(e.message).slice(0,160);btn.disabled=false}}
 }});
}}
</script></body></html>"#,
        total = state.repositories.len(),
        selected = selected,
        reviewed = reviewed
    )
}
fn private_session() -> Result<String, String> {
    use std::io::Read;
    let mut secret = [0u8; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut secret))
        .map_err(|_| "LOCAL_SESSION_ENTROPY_UNAVAILABLE")?;
    Ok(secret
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>())
}

pub fn serve(path: &Path, gh: &str) -> Result<(), String> {
    use std::io::Read;
    use std::net::TcpListener;
    use std::time::Duration;
    let _ = load(path)?;
    let session = private_session()?;
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|_| "LOCAL_DASHBOARD_LOOPBACK_BIND_FAILED")?;
    let addr = listener
        .local_addr()
        .map_err(|_| "DASHBOARD_PORT_UNAVAILABLE")?;
    println!("R30_LOCAL_DASHBOARD=http://127.0.0.1:{}/", addr.port());
    println!("R30_SECURITY=LOOPBACK_ONLY_NO_REMOTE_LISTENER_NO_PROVIDER_WRITES");
    let origin = format!("http://127.0.0.1:{}", addr.port());
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            continue;
        };
        if !stream.peer_addr().is_ok_and(|a| a.ip().is_loopback()) {
            continue;
        }
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let mut buf = Vec::new();
        let mut tmp = [0u8; 2048];
        let mut header_end = None;
        while buf.len() < 16_384 {
            let Ok(n) = stream.read(&mut tmp) else {
                break;
            };
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            header_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
            if header_end.is_some() {
                break;
            }
        }
        let Some(end) = header_end else {
            continue;
        };
        let head = String::from_utf8_lossy(&buf[..end]);
        let mut lines = head.split("\r\n");
        let method_path = lines.next().unwrap_or("");
        let mut host = None;
        let mut request_origin = None;
        let mut token = None;
        let mut content_length = None;
        let mut content_type = None;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                match k.trim().to_ascii_lowercase().as_str() {
                    "host" => host = Some(v.trim()),
                    "origin" => request_origin = Some(v.trim()),
                    "x-r30-session" => token = Some(v.trim()),
                    "content-length" => content_length = v.trim().parse::<usize>().ok(),
                    "content-type" => content_type = Some(v.trim()),
                    _ => {}
                }
            }
        }
        let canonical_host = format!("127.0.0.1:{}", addr.port());
        if host != Some(canonical_host.as_str()) {
            write_http(
                &mut stream,
                403,
                "application/json",
                "{\"error\":\"UNTRUSTED_HOST\"}",
            );
            continue;
        }
        if method_path == "GET / HTTP/1.1" {
            match load(path) {
                Ok(state) => write_http(
                    &mut stream,
                    200,
                    "text/html; charset=utf-8",
                    &dashboard_html(&state, &session),
                ),
                Err(_) => write_http(
                    &mut stream,
                    503,
                    "application/json",
                    "{\"error\":\"PRIVATE_STATE_UNAVAILABLE\"}",
                ),
            }
            continue;
        }
        if method_path == "GET /health HTTP/1.1" {
            write_http(
                &mut stream,
                200,
                "application/json",
                "{\"status\":\"LOCAL_ONLY\"}",
            );
            continue;
        }
        if !matches!(
            method_path,
            "POST /select HTTP/1.1" | "POST /review HTTP/1.1"
        ) || request_origin != Some(origin.as_str())
            || token != Some(session.as_str())
            || content_type != Some("application/json")
            || !content_length.is_some_and(|n| (1..=1024).contains(&n))
        {
            write_http(
                &mut stream,
                403,
                "application/json",
                "{\"error\":\"LOCAL_SESSION_OR_REQUEST_REJECTED\"}",
            );
            continue;
        }
        let len = content_length.unwrap_or(0);
        let mut body = buf[end + 4..].to_vec();
        while body.len() < len {
            let Ok(n) = stream.read(&mut tmp) else {
                break;
            };
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
            if body.len() > 1024 {
                break;
            }
        }
        if body.len() != len {
            write_http(
                &mut stream,
                400,
                "application/json",
                "{\"error\":\"INVALID_REQUEST_SIZE\"}",
            );
            continue;
        }
        let payload: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => {
                write_http(
                    &mut stream,
                    400,
                    "application/json",
                    "{\"error\":\"INVALID_JSON\"}",
                );
                continue;
            }
        };
        let id = payload.get("repo_id").and_then(|v| v.as_u64()).unwrap_or(0);
        let result = if method_path.starts_with("POST /select ") {
            match payload.get("selected").and_then(|v| v.as_bool()) {
                Some(selected) => set_selected(path, id, selected),
                None => Err("MISSING_SELECTION_FLAG".into()),
            }
        } else {
            let pr_number = payload.get("pr_number").and_then(|n| n.as_u64());
            review(path, id, gh, pr_number)
        };
        match result {
            Ok(_) => write_http(&mut stream, 200, "application/json", "{\"status\":\"OK\"}"),
            Err(e) => {
                let msg = serde_json::json!({"error":e}).to_string();
                write_http(&mut stream, 400, "application/json", &msg);
            }
        }
    }
    Ok(())
}
fn write_http(stream: &mut std::net::TcpStream, status: u16, content_type: &str, body: &str) {
    use std::io::Write;
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        _ => "Unavailable",
    };
    let nonce = if content_type.starts_with("text/html") {
        body.split("<script nonce=\"")
            .nth(1)
            .and_then(|rest| rest.split('\"').next())
            .filter(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or("script-not-authorized")
    } else {
        "script-not-authorized"
    };
    let headers = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; connect-src 'self'; form-action 'none'; base-uri 'none'\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

/// Optional integration with the existing R27/R29 Rust Compose compatibility
/// gate. No test execution, GitHub writes, local staging or live upgrade.
/// Caller must supply an existing source/receipt configuration and a fresh PR.
pub fn qualify_selected_pr(
    state_path: &Path,
    gh: &str,
    repository_id: u64,
    pr_number: u64,
    config_path: &Path,
) -> Result<Workspace, String> {
    // Re-fetch current Github owner, repo, target PR and source diff first;
    // revocation or changed PR commits fail closed before local inspection.
    let state = review(state_path, repository_id, gh, Some(pr_number))?;
    let r = state
        .repositories
        .iter()
        .find(|r| r.id == repository_id && r.selected)
        .ok_or("SELECTED_REPOSITORY_NOT_FOUND")?;
    let selected = r
        .review
        .as_ref()
        .and_then(|v| v.explicit_pr.as_ref())
        .ok_or("EXACT_GITHUB_PR_NOT_REVIEWED")?;
    let meta = fs::symlink_metadata(config_path).map_err(|_| "SYSTEM_LOCAL_CONFIG_NOT_FOUND")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 128 * 1024 {
        return Err("SYSTEM_LOCAL_CONFIG_INVALID_OR_UNSAFE".into());
    }
    let content = fs::read(config_path).map_err(|_| "SYSTEM_LOCAL_CONFIG_UNREADABLE")?;
    let base = config_path
        .parent()
        .ok_or("SYSTEM_LOCAL_CONFIG_PARENT_MISSING")?;
    let request = crate::system_upgrade::parse_request(&content, base)?;

    // The local fixture or source must be independently named as the
    // **selected Github repository**. Never attach another project/PR's
    // successful evidence as if it belonged to this PR.
    let origin = crate::git_source::git(&request.repo, &["config", "--get", "remote.origin.url"])?;
    let origin = std::str::from_utf8(&origin)
        .map_err(|_| "LOCAL_GIT_ORIGIN_NOT_UTF8")?
        .trim();
    let name = &r.full_name;
    let allowed = [
        format!("https://github.com/{name}"),
        format!("https://github.com/{name}.git"),
        format!("git@github.com:{name}.git"),
        format!("ssh://git@github.com/{name}.git"),
    ];
    if !allowed.iter().any(|url| url == origin) {
        return Err("LOCAL_SYSTEM_SOURCE_ORIGIN_NOT_SELECTED_GITHUB_REPO".into());
    }
    let report = crate::system_upgrade::qualify(request)?.report;
    if report.baseline_commit != selected.base_sha || report.candidate_commit != selected.head_sha {
        return Err("LOCAL_SYSTEM_EVIDENCE_COMMITS_NOT_EXACT_GITHUB_PR".into());
    }
    if report.production_compatibility_proven
        || report.one_click_live_upgrade_authorized
        || report.performed_test_execution
        || report.performed_provider_mutations
    {
        return Err("SYSTEM_GATE_CLAIMS_UNAUTHORIZED_ACTION".into());
    }
    let gate = BoundSystemGate {
        decision: report.decision.into(),
        baseline_commit: report.baseline_commit,
        candidate_commit: report.candidate_commit,
        affected_services: report.affected_services,
        covered_checks: report.covered_required_checks,
        required_checks: report.total_required_checks,
        test_evidence_origin: report.test_evidence_origin.into(),
        source_bound_to_selected_pr: true,
        actual_test_execution_by_this_command: false,
        live_upgrade_authorized: false,
    };
    let mut state = load(state_path)?;
    let entry = state
        .repositories
        .iter_mut()
        .find(|r| r.id == repository_id && r.selected)
        .ok_or("SELECTED_REPOSITORY_DISAPPEARED")?;
    let review = entry
        .review
        .as_mut()
        .ok_or("REPOSITORY_REVIEW_DISAPPEARED")?;
    review.decision = if gate.decision == "BLOCKED" {
        "BLOCKED".into()
    } else {
        // Even a complete local self-reported R29 REVIEW never equals
        // signed CI provenance or safe production authorization.
        "UNKNOWN".into()
    };
    review
        .reasons
        .push("R29_COMPOSE_GATE_EXECUTED_WITH_EXACT_PR_COMMITS_LOCAL_UNATTESTED".into());
    review.r29_system_upgrade_gate = gate.decision.clone();
    review.system_gate = Some(gate);
    save(state_path, &state)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn synthetic_repo(id: u64) -> serde_json::Value {
        let full_name = format!("example/r{id}");
        serde_json::json!({
            "id":id,"full_name":full_name,"html_url":format!("https://github.com/{full_name}"),
            "private":true,"archived":false,"disabled":false,"fork":false,
            "language":"Rust","default_branch":"main","pushed_at":"2026-11-22T10:00:00Z"
        })
    }
    struct PrivateFolder(std::path::PathBuf);
    impl PrivateFolder {
        fn new() -> Self {
            let name = format!(
                "r30-test-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let path = std::env::temp_dir().join(name);
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }
    }
    impl Drop for PrivateFolder {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn state() -> Workspace {
        Workspace {
            schema: SCHEMA.into(),
            provider: "github".into(),
            auth_model: "EXISTING_GITHUB_CLI_USER_SESSION".into(),
            account: "example".into(),
            account_id: 21,
            installation_id: None,
            synced_unix: now(),
            repository_coverage: "COMPLETE_API_PAGINATION_WITHIN_1000".into(),
            repositories: vec![github_repo(&synthetic_repo(10), false, None).unwrap()],
            provider_writes_authorized: false,
            automated_upgrade_authorized: false,
        }
    }
    #[test]
    fn repository_identity_and_permissions_are_not_inferred_from_names() {
        let r = github_repo(&synthetic_repo(10), false, None).unwrap();
        assert!(r.private && !r.selected && r.language.as_deref() == Some("Rust"));
        assert_eq!(r.recommendation, "LIKELY_ACTIVE_SOURCE");
        let mut bad = synthetic_repo(10);
        bad["html_url"] = "https://not-github.example/phish".into();
        assert!(github_repo(&bad, false, None).is_err());
        assert!(!safe_full_name("../foo") && !safe_full_name("org/../repo"));
        assert!(safe_full_name("org/repo.v2"));
        assert_eq!(encode_ref("feature/x"), "feature%2Fx");
    }
    #[test]
    fn signed_or_live_permission_cannot_be_added_to_workspace_json() {
        let mut s = state();
        s.provider_writes_authorized = true;
        assert!(validate(&s).is_err());
        s.provider_writes_authorized = false;
        s.automated_upgrade_authorized = true;
        assert!(validate(&s).is_err());
        s.automated_upgrade_authorized = false;
        s.installation_id = Some(5);
        assert!(validate(&s).is_err());
    }
    #[test]
    fn private_atomic_persistent_selected_state_and_revocation() {
        let tmp = PrivateFolder::new();
        let file = tmp.0.join("workspace.json");
        save(&file, &state()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let s = set_selected(&file, 10, true).unwrap();
        assert!(s.repositories[0].selected);
        assert!(!s.automated_upgrade_authorized);
        assert!(set_selected(&file, 11, true).is_err());
        assert!(load(&file).unwrap().repositories[0].selected);
        assert!(!set_selected(&file, 10, false).unwrap().repositories[0].selected);
    }
    #[test]
    fn unsafe_filesystem_paths_and_symlink_never_used_for_workspace_data() {
        let tmp = PrivateFolder::new();
        let file = tmp.0.join("workspace.json");
        save(&file, &state()).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&file, tmp.0.join("link.json")).unwrap();
            assert!(load(&tmp.0.join("link.json")).is_err());
            assert!(save(&tmp.0.join("link.json"), &state()).is_err());
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp.0, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(load(&file).is_err());
            assert!(save(&file, &state()).is_err());
        }
    }
    #[test]
    fn local_dashboard_escapes_untrusted_github_data_and_never_invents_pass() {
        let mut s = state();
        s.repositories[0].language = Some("<img src=x onerror=alert(1)>".into());
        let html = dashboard_html(&s, &"f".repeat(64));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("NINCS VIZSGÁLAT"));
        assert!(html.contains("Projekt kiválasztása"));
        assert!(!html.contains("script src="));
        assert!(html.contains("const session="));
    }
    #[test]
    fn github_compare_separator_allowed_but_traversal_and_remote_url_denied() {
        assert_eq!(
            bound_gh(
                "/definitely/not-a-command",
                "repos/example/r10/compare/aaaaaaaa...bbbbbbbb"
            )
            .unwrap_err(),
            "GITHUB_CLI_NOT_AVAILABLE"
        );
        for endpoint in [
            "https://attacker.example/api",
            "repos/example/../secrets",
            "repos/example/compare/a..b",
            "repos/example/foo #attack",
        ] {
            assert_eq!(
                bound_gh("/definitely/not-a-command", endpoint).unwrap_err(),
                "GH_PROVIDER_ENDPOINT_NOT_ALLOWED"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn authenticated_listing_two_pages_preserves_explicit_selections_and_drops_revoked() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = PrivateFolder::new();
        let page1 = (1..=100).map(synthetic_repo).collect::<Vec<_>>();
        let page2 = vec![synthetic_repo(101)];
        let p1 = tmp.0.join("page1.json");
        let p2 = tmp.0.join("page2.json");
        fs::write(&p1, serde_json::to_vec(&page1).unwrap()).unwrap();
        fs::write(&p2, serde_json::to_vec(&page2).unwrap()).unwrap();
        let mock = tmp.0.join("gh");
        let program = format!(
            "#!/bin/sh\ncase \"$*\" in\n *' user') printf '%s' '{{\"id\":21,\"login\":\"example\"}}';;\n *'&page=1&'*) cat '{}';;\n *'&page=2&'*) cat '{}';;\n *) exit 44;;\nesac\n",
            p1.display(),
            p2.display()
        );
        fs::write(&mock, program).unwrap();
        fs::set_permissions(&mock, fs::Permissions::from_mode(0o700)).unwrap();
        let f = tmp.0.join("workspace.json");
        let initial = sync(&f, mock.to_str().unwrap()).unwrap();
        assert_eq!(initial.repositories.len(), 101);
        set_selected(&f, 101, true).unwrap();
        let after = sync(&f, mock.to_str().unwrap()).unwrap();
        assert_eq!(after.repositories.iter().filter(|r| r.selected).count(), 1);
        assert!(
            after
                .repositories
                .iter()
                .find(|r| r.id == 101)
                .unwrap()
                .selected
        );
        fs::write(&p2, b"[]").unwrap();
        let revoked = sync(&f, mock.to_str().unwrap()).unwrap();
        assert_eq!(revoked.repositories.len(), 100);
        assert!(!revoked.repositories.iter().any(|r| r.id == 101));
    }

    #[test]
    fn persisted_r29_gate_must_match_selected_pr_and_never_grants_live_rights() {
        let mut s = state();
        s.repositories[0].selected = true;
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        let pr = UpgradePr {
            number: 5,
            title: "database upgrade".into(),
            html_url: "https://github.com/example/r10/pull/5".into(),
            head_sha: b.clone(),
            base_sha: a.clone(),
            author: "example".into(),
            draft: true,
            kind: "POSSIBLE_UPGRADE".into(),
        };
        let gate = BoundSystemGate {
            decision: "REVIEW".into(),
            baseline_commit: a.clone(),
            candidate_commit: b.clone(),
            affected_services: vec!["api".into(), "db".into()],
            covered_checks: 3,
            required_checks: 3,
            test_evidence_origin: "LOCAL_USER_SUPPLIED_SHA_PINNED_UNATTESTED".into(),
            source_bound_to_selected_pr: true,
            actual_test_execution_by_this_command: false,
            live_upgrade_authorized: false,
        };
        s.repositories[0].review = Some(MaintenanceReview {
            schema: "tredven.upstream.github-maintenance-review.v1".into(),
            repository_id: 10,
            source_commit: a.clone(),
            source_tree: b.clone(),
            manifest_paths: vec!["compose.yaml".into()],
            tech_signals: vec!["Compose".into()],
            service_connections: vec![],
            ci_paths: vec![],
            open_upgrade_prs: vec![],
            explicit_pr: Some(pr),
            pr_source_impact: None,
            system_gate: Some(gate),
            tree_complete: true,
            pull_list_complete: true,
            decision: "UNKNOWN".into(),
            reasons: vec![],
            evidence_origin: "AUTHENTICATED_GITHUB_REST_METADATA_NOT_RUNTIME_ATTESTATION".into(),
            integration_e2e_proven: false,
            r29_system_upgrade_gate: "REVIEW".into(),
            live_upgrade_authorized: false,
        });
        validate(&s).unwrap();
        s.repositories[0]
            .review
            .as_mut()
            .unwrap()
            .system_gate
            .as_mut()
            .unwrap()
            .live_upgrade_authorized = true;
        assert!(validate(&s).is_err());
        s.repositories[0]
            .review
            .as_mut()
            .unwrap()
            .system_gate
            .as_mut()
            .unwrap()
            .live_upgrade_authorized = false;
        s.repositories[0]
            .review
            .as_mut()
            .unwrap()
            .system_gate
            .as_mut()
            .unwrap()
            .candidate_commit = "c".repeat(40);
        assert!(validate(&s).is_err());
        s.repositories[0]
            .review
            .as_mut()
            .unwrap()
            .system_gate
            .as_mut()
            .unwrap()
            .candidate_commit = b;
        s.repositories[0].review.as_mut().unwrap().decision = "REVIEW".into();
        assert!(validate(&s).is_err());
    }
}
