//! Read-only inspection of **local Git objects**. This does not attest the remote publisher
//! and never fetches, checks out, executes hooks, runs tests, or edits a repository.
use crate::{
    Check, CheckStatus, CompareCoverage, INPUT_SCHEMA, PreflightInput, PreflightReport, Release,
    inspect_with_origin,
};
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

const MAX_DIFF_BYTES: usize = 2_000_000;
const MAX_PATHS: usize = 10_000;

fn safe_tag(tag: &str) -> bool {
    tag.len() <= 64
        && tag.len() >= 2
        && tag
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-_+".contains(&c))
        && !tag.starts_with('-')
        && !tag.starts_with('.')
        && !tag.ends_with('.')
        && !tag.contains("..")
        && !tag.contains("@{")
}

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    // Restrict inherited Git configuration and execution hooks. Git must be installed on PATH.
    // No shell is involved; tags are constrained to a safe input alphabet.
    let mut cmd = Command::new("git");
    cmd.env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .arg("--no-pager")
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.fsmonitor=false"])
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(["-c", "diff.external="])
        .args(args);
    let output = cmd.output().map_err(|_| "GIT_BINARY_UNAVAILABLE")?;
    if !output.status.success() {
        return Err("LOCAL_GIT_COMMAND_FAILED_OR_UNVERIFIED_REF".into());
    }
    if output.stdout.len() > MAX_DIFF_BYTES {
        return Err("LOCAL_GIT_OUTPUT_TOO_LARGE".into());
    }
    Ok(output.stdout)
}

fn parse_git_sha(bytes: &[u8]) -> Result<String, String> {
    let s = std::str::from_utf8(bytes)
        .map_err(|_| "NON_UTF8_COMMIT_ID")?
        .trim();
    if s.len() != 40 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("INVALID_LOCAL_COMMIT_SHA".into());
    }
    Ok(s.to_ascii_lowercase())
}

/// Compare two *local, named Git tags* without checking out or fetching sources.
///
/// The local tag-to-commit resolution is independently checked against the on-disk
/// object graph, but it does **not** authenticate a remote repository or release.
pub fn inspect_local_git(
    repo: &Path,
    project: &str,
    baseline_tag: &str,
    candidate_tag: &str,
) -> Result<PreflightReport, String> {
    if !safe_tag(baseline_tag) || !safe_tag(candidate_tag) {
        return Err("INVALID_LOCAL_GIT_TAG".into());
    }
    let meta = fs::symlink_metadata(repo).map_err(|_| "LOCAL_GIT_REPO_UNAVAILABLE")?;
    if !meta.file_type().is_dir() {
        return Err("LOCAL_GIT_REPO_MUST_BE_DIRECTORY_NOT_SYMLINK".into());
    }
    let repo = repo
        .canonicalize()
        .map_err(|_| "LOCAL_GIT_REPO_UNAVAILABLE")?;
    let top = git(&repo, &["rev-parse", "--show-toplevel"])?;
    let top = std::str::from_utf8(&top)
        .map_err(|_| "LOCAL_GIT_ROOT_NON_UTF8")?
        .trim();
    if top != repo.to_str().ok_or("LOCAL_GIT_ROOT_NON_UTF8")? {
        return Err("LOCAL_GIT_REPO_ROOT_REQUIRED".into());
    }

    let from_ref = format!("refs/tags/{baseline_tag}^{{commit}}");
    let to_ref = format!("refs/tags/{candidate_tag}^{{commit}}");
    let from = parse_git_sha(&git(
        &repo,
        &["rev-parse", "--verify", "--end-of-options", &from_ref],
    )?)?;
    let to = parse_git_sha(&git(
        &repo,
        &["rev-parse", "--verify", "--end-of-options", &to_ref],
    )?)?;
    let files = git(
        &repo,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--name-only",
            "-z",
            &from,
            &to,
            "--",
        ],
    )?;
    if !files.is_empty() && files.last() != Some(&0) {
        return Err("GIT_DIFF_NOT_NUL_TERMINATED".into());
    }
    let mut paths = Vec::new();
    for name in files.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        if paths.len() >= MAX_PATHS {
            return Err("GIT_DIFF_TOO_MANY_PATHS".into());
        }
        let name = std::str::from_utf8(name)
            .map_err(|_| "GIT_DIFF_PATH_NON_UTF8")?
            .to_owned();
        paths.push(name);
    }
    let request = PreflightInput {
        schema: INPUT_SCHEMA.into(),
        project: project.to_owned(),
        baseline: Release {
            tag: baseline_tag.into(),
            commit: Some(from),
        },
        candidate: Release {
            tag: candidate_tag.into(),
            commit: Some(to),
        },
        source_verified: Some(true), // local *objects*, not upstream publisher
        compare_coverage: CompareCoverage::Complete,
        changed_paths: paths,
        checks: vec![Check {
            name: "runtime-tests".into(),
            status: CheckStatus::NotRun,
        }],
    };
    inspect_with_origin(request, "LOCAL_GIT_OBJECTS_REMOTE_UNATTESTED")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ref_injection_and_aliases() {
        for bad in [
            "--help", "../main", "foo/bar", ".", ".hidden", "v1..2", "HEAD", "",
        ] {
            // HEAD is syntactically allowed as tag name, but Git can only resolve refs/tags/HEAD,
            // not the unqualified branch/ref HEAD.
            if bad == "HEAD" {
                continue;
            }
            assert!(!safe_tag(bad), "{bad}");
        }
        assert!(safe_tag("v0.9.3"));
        assert!(safe_tag("v1.0.0-rc.2"));
    }
}
