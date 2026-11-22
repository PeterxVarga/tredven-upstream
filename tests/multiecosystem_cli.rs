//! R26: generic project ecosystems, strict Git source selection, no network.
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tredven_upstream::lockfile;

static COUNT: AtomicUsize = AtomicUsize::new(0);
struct Repo(PathBuf);
impl Repo {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "tredven-r26-{}-{nanos}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).unwrap();
        let repo = Self(path);
        repo.git(&["init", "-q"]);
        repo.git(&["config", "user.name", "R26 fixture"]);
        repo.git(&["config", "user.email", "r26@example.invalid"]);
        repo
    }
    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.0)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }
    fn add(&self, path: &str, bytes: &[u8]) {
        let p = self.0.join(path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, bytes).unwrap();
    }
    fn save_tag(&self, tag: &str) -> String {
        self.git(&["add", "."]);
        self.git(&["commit", "-qm", tag]);
        self.git(&["tag", tag]);
        self.git(&["rev-parse", "HEAD"])
    }
}
impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn npm_is_auto_detected_from_real_git_objects_not_worktree() {
    let r = Repo::new();
    let a = br#"{"name":"npm-fixture","lockfileVersion":3,"packages":{}}"#;
    let b = br#"{"name":"npm-fixture","lockfileVersion":3,"packages":{"node_modules/z":{}}}"#;
    r.add("package-lock.json", a);
    let base = r.save_tag("v1.0");
    r.add("package-lock.json", b);
    let to = r.save_tag("v1.1");
    // Deliberately remove the working file; only two pinned Git trees count.
    fs::remove_file(r.0.join("package-lock.json")).unwrap();
    assert_eq!(
        lockfile::select(&r.0, &base, &to, None).unwrap(),
        "package-lock.json"
    );
    assert_eq!(
        lockfile::snapshot(&r.0, &base, "package-lock.json").unwrap(),
        a
    );
    assert_eq!(
        lockfile::snapshot(&r.0, &to, "package-lock.json").unwrap(),
        b
    );
}

#[test]
fn nested_python_manifest_requires_explicit_path_and_is_pinned_to_both_git_versions() {
    let r = Repo::new();
    r.add("services/api/requirements.txt", b"flask==2.2.0\n");
    let base = r.save_tag("v1.0");
    r.add("services/api/requirements.txt", b"flask==3.0.3\n");
    let to = r.save_tag("v1.1");
    assert_eq!(
        lockfile::select(&r.0, &base, &to, None).unwrap_err(),
        "NO_SUPPORTED_ROOT_LOCKFILE_USE_EXPLICIT_PATH"
    );
    assert_eq!(
        lockfile::select(&r.0, &base, &to, Some("services/api/requirements.txt")).unwrap(),
        "services/api/requirements.txt"
    );
    assert_eq!(
        lockfile::snapshot(&r.0, &to, "services/api/requirements.txt").unwrap(),
        b"flask==3.0.3\n"
    );
    assert_eq!(r.git(&["status", "--porcelain"]), "");
}

#[test]
fn multiple_ecosystems_never_count_as_single_complete_scan() {
    let r = Repo::new();
    r.add("Cargo.lock", b"version = 3\n");
    r.add(
        "package-lock.json",
        br#"{"lockfileVersion":3,"packages":{}}"#,
    );
    let base = r.save_tag("v1.0");
    r.add("Cargo.lock", b"version = 3\n# changed\n");
    let to = r.save_tag("v1.1");
    assert_eq!(
        lockfile::select(&r.0, &base, &to, None).unwrap_err(),
        "AMBIGUOUS_ROOT_LOCKFILES_USE_EXPLICIT_PATH"
    );
    assert_eq!(
        lockfile::select(&r.0, &base, &to, Some("Cargo.lock")).unwrap(),
        "Cargo.lock"
    );
    assert_eq!(
        lockfile::select(&r.0, &base, &to, Some("package-lock.json")).unwrap(),
        "package-lock.json"
    );
}

#[test]
fn unsupported_traversal_and_missing_tag_snapshot_fail_before_upstream_download() {
    let r = Repo::new();
    r.add("Cargo.lock", b"version = 3\n");
    let base = r.save_tag("v1.0");
    r.add("Cargo.lock", b"version = 3\n# updated\n");
    let to = r.save_tag("v1.1");
    for invalid in [
        "../Cargo.lock",
        "x/../package-lock.json",
        "Dockerfile",
        "node_modules/.package-lock.json",
        "/etc/passwd",
    ] {
        assert_eq!(
            lockfile::select(&r.0, &base, &to, Some(invalid)).unwrap_err(),
            "UNSUPPORTED_OR_UNSAFE_LOCKFILE_PATH"
        );
    }
    assert_eq!(
        lockfile::select(&r.0, &base, &to, Some("go.mod")).unwrap_err(),
        "LOCKFILE_NOT_IN_BOTH_PINNED_SOURCE_COMMITS"
    );
    let empty_cache = r.0.join("uncreated-cache");
    let out = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"))
        .args(["review-local", "--repo"])
        .arg(&r.0)
        .args([
            "--from",
            "v1.0",
            "--to",
            "v1.1",
            "--lockfile",
            "../Cargo.lock",
            "--install-pinned-osv",
            "--allow-public-osv-network",
        ])
        .env("XDG_CACHE_HOME", &empty_cache)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("UNSUPPORTED_OR_UNSAFE_LOCKFILE_PATH"));
    assert!(!empty_cache.exists());
}

#[test]
#[cfg(unix)]
fn git_symlink_to_dependency_file_is_never_followed() {
    use std::os::unix::fs::symlink;
    let r = Repo::new();
    r.add("outside.json", br#"{"lockfileVersion":3}"#);
    symlink("outside.json", r.0.join("package-lock.json")).unwrap();
    let base = r.save_tag("v1.0");
    r.add("README.md", b"new commit\n");
    let to = r.save_tag("v1.1");
    assert_eq!(
        lockfile::select(&r.0, &base, &to, Some("package-lock.json")).unwrap_err(),
        "LOCKFILE_NOT_REGULAR_GIT_BLOB"
    );
}
