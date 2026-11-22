//! Source-bound selection of one OSV-supported project lockfile/manifest.
//! This does not claim whole-project dependency coverage for mixed ecosystems.
use crate::git_source::git;
use std::path::Path;

const MAX_LOCK_BYTES: usize = 2_000_000;
const ROOT_FILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "go.mod",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
    "pdm.lock",
    "uv.lock",
    "pylock.toml",
    "pom.xml",
    "gradle.lockfile",
    "buildscript-gradle.lockfile",
    "composer.lock",
    "Gemfile.lock",
    "gems.locked",
    "packages.lock.json",
    "packages.config",
    "deps.json",
    "conan.lock",
    "pubspec.lock",
    "package_config.json",
    "mix.lock",
    "renv.lock",
    "cabal.project.freeze",
    "stack.yaml.lock",
];

pub fn supported(path: &str) -> bool {
    if path.is_empty() || path.len() > 240 || path.starts_with('/') || path.ends_with('/') {
        return false;
    }
    let parts: Vec<_> = path.split('/').collect();
    if parts.iter().any(|part| {
        part.is_empty()
            || part.starts_with('-')
            || *part == "."
            || *part == ".."
            || !part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    }) {
        return false;
    }
    ROOT_FILES.contains(parts.last().unwrap())
        || path == "gradle/verification-metadata.xml"
        || path.ends_with("/gradle/verification-metadata.xml")
}

fn read_blob(repo: &Path, commit: &str, path: &str) -> Result<Vec<u8>, String> {
    if !supported(path) {
        return Err("UNSUPPORTED_OR_UNSAFE_LOCKFILE_PATH".into());
    }
    // Checking the Git tree also rejects symlinks and submodules, including
    // nested paths, without ever checking out or executing untrusted sources.
    let tree = git(repo, &["ls-tree", "-z", commit, "--", path])?;
    let mut entries = tree.split(|b| *b == 0).filter(|x| !x.is_empty());
    let entry = entries
        .next()
        .ok_or("LOCKFILE_NOT_IN_BOTH_PINNED_SOURCE_COMMITS")?;
    if entries.next().is_some() || !entry.starts_with(b"100644 blob ") {
        return Err("LOCKFILE_NOT_REGULAR_GIT_BLOB".into());
    }
    let tab = entry
        .iter()
        .position(|b| *b == b'\t')
        .ok_or("LOCKFILE_GIT_TREE_ENTRY_INVALID")?;
    let observed_name = &entry[tab + 1..];
    if observed_name != path.as_bytes() {
        return Err("LOCKFILE_GIT_TREE_PATH_MISMATCH".into());
    }
    let bytes = git(repo, &["show", &format!("{commit}:{path}")])?;
    if bytes.is_empty() || bytes.len() > MAX_LOCK_BYTES {
        return Err("LOCKFILE_BYTES_OUT_OF_BOUNDS".into());
    }
    Ok(bytes)
}

pub fn snapshot(repo: &Path, commit: &str, path: &str) -> Result<Vec<u8>, String> {
    read_blob(repo, commit, path)
}

/// Select one supported root lockfile automatically, but never claim mixed
/// project coverage when there are several candidates. Nested paths require
/// explicit --lockfile, and must exist in both selected source Git objects.
pub fn select(
    repo: &Path,
    baseline_commit: &str,
    candidate_commit: &str,
    explicit: Option<&str>,
) -> Result<String, String> {
    let name = if let Some(path) = explicit {
        if !supported(path) {
            return Err("UNSUPPORTED_OR_UNSAFE_LOCKFILE_PATH".into());
        }
        path.to_owned()
    } else {
        let tree = git(
            repo,
            &["ls-tree", "--name-only", "-z", candidate_commit, "--"],
        )?;
        let mut choices = Vec::new();
        for part in tree.split(|b| *b == 0).filter(|x| !x.is_empty()) {
            if let Ok(path) = std::str::from_utf8(part) {
                if ROOT_FILES.contains(&path) {
                    choices.push(path);
                }
            }
        }
        match choices.as_slice() {
            [] => return Err("NO_SUPPORTED_ROOT_LOCKFILE_USE_EXPLICIT_PATH".into()),
            [only] => (*only).to_owned(),
            _ => return Err("AMBIGUOUS_ROOT_LOCKFILES_USE_EXPLICIT_PATH".into()),
        }
    };
    read_blob(repo, baseline_commit, &name)?;
    read_blob(repo, candidate_commit, &name)?;
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_upstream_ecosystems_and_safe_nested_paths() {
        for name in [
            "Cargo.lock",
            "package-lock.json",
            "frontend/pnpm-lock.yaml",
            "apps/web/yarn.lock",
            "services/api/poetry.lock",
            "go.mod",
            "pom.xml",
            "buildscript-gradle.lockfile",
            "src/gradle/verification-metadata.xml",
            "composer.lock",
            "packages.lock.json",
            "Gemfile.lock",
            "pylock.toml",
            "uv.lock",
            "bun.lock",
        ] {
            assert!(supported(name), "{name}");
        }
        for name in [
            "",
            ".",
            "..",
            "../Cargo.lock",
            "x/../Cargo.lock",
            "/Cargo.lock",
            "x//Cargo.lock",
            "C:\\Cargo.lock",
            "-bad/Cargo.lock",
            "package.json",
            "Dockerfile",
            "x/.hidden/package-lock.json ",
            "Cargo.lock\n",
            "x/Cargo.lock/.",
            "not-a-lockfile.txt",
        ] {
            assert!(!supported(name), "{name:?}");
        }
    }
}
