//! R18: explicit opt-in, SHA-pinned upstream OSV-Scanner local cache.
//! This is NOT a bundled binary, an upstream signing assertion or a release grant.
//! Only the verified Linux x86-64 OSV-Scanner v2.7.1 release asset is supported.
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub const OSV_SHA256: &str = "fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8";
const OSV_SIZE: u64 = 58_187_936;
const OSV_URL: &str =
    "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_linux_amd64";
const CACHE_NAME: &str = "osv-scanner-v2.7.1-linux-amd64";

fn safe_dir(path: &Path, create: bool) -> Result<(), String> {
    if create && fs::symlink_metadata(path).is_err() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|_| "OSV_CACHE_PRIVATE_DIRECTORY_CREATE_FAILED")?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir(path).map_err(|_| "OSV_CACHE_PRIVATE_DIRECTORY_CREATE_FAILED")?;
        }
    }
    let meta = fs::symlink_metadata(path).map_err(|_| "OSV_CACHE_DIRECTORY_UNAVAILABLE")?;
    if !meta.file_type().is_dir() {
        return Err("OSV_CACHE_DIRECTORY_SYMLINK_OR_NOT_DIRECTORY".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o022 != 0 {
            return Err("OSV_CACHE_DIRECTORY_WRITABLE_BY_OTHERS".into());
        }
    }
    Ok(())
}

fn cache_folder() -> Result<PathBuf, String> {
    let home = env::var_os("HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .ok_or("OSV_CACHE_HOME_UNAVAILABLE")?;
    if !home.is_absolute() {
        return Err("OSV_CACHE_HOME_NOT_ABSOLUTE".into());
    }
    let base = if let Some(xdg) = env::var_os("XDG_CACHE_HOME").filter(|s| !s.is_empty()) {
        let path = PathBuf::from(xdg);
        if !path.is_absolute() {
            return Err("OSV_CACHE_XDG_PATH_NOT_ABSOLUTE".into());
        }
        path
    } else {
        safe_dir(&home, false)?;
        home.join(".cache")
    };
    // Only the conventional HOME/.cache may be created here. A custom XDG
    // cache base must already exist, avoiding creation in unexpected paths.
    safe_dir(&base, base == home.join(".cache"))?;
    let app = base.join("tredven-upstream");
    safe_dir(&app, true)?;
    let tools = app.join("tools");
    safe_dir(&tools, true)?;
    Ok(tools)
}

fn verified_existing(path: &Path) -> Result<bool, String> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("OSV_CACHE_BINARY_METADATA_FAILED".into()),
    };
    if !meta.file_type().is_file() || meta.len() != OSV_SIZE {
        return Err("OSV_CACHE_BINARY_NOT_PINNED_REGULAR_FILE".into());
    }
    let mut file = File::open(path).map_err(|_| "OSV_CACHE_BINARY_READ_FAILED")?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| "OSV_CACHE_BINARY_READ_FAILED")?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    if format!("{:x}", digest.finalize()) != OSV_SHA256 {
        return Err("OSV_CACHE_BINARY_SHA256_MISMATCH".into());
    }
    Ok(true)
}

/// Called ONLY after both explicit CLI flags have been validated.
/// First use downloads the exact official HTTPS release asset into a private
/// per-user cache; repeat runs verify the cached bytes without a download.
/// Never execute a file before the exact SHA-256 AND size have been checked.
pub fn ensure_pinned() -> Result<(PathBuf, &'static str), String> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err("OSV_PINNED_BOOTSTRAP_PLATFORM_NOT_SUPPORTED".into());
    }
    let folder = cache_folder()?;
    let target = folder.join(CACHE_NAME);
    if verified_existing(&target)? {
        return Ok((target, OSV_SHA256));
    }
    let curl = ["/usr/bin/curl", "/bin/curl"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .ok_or("OSV_BOOTSTRAP_REQUIRES_SYSTEM_CURL")?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "OSV_BOOTSTRAP_CLOCK_UNAVAILABLE")?
        .as_nanos();
    let tmp = folder.join(format!(".osv-{stamp}-{}", std::process::id()));
    let result = (|| -> Result<(), String> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|_| "OSV_BOOTSTRAP_TEMP_CREATE_FAILED")?;
        let status = Command::new(curl)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg("--fail")
            .arg("--location")
            .args(["--proto", "=https", "--proto-redir", "=https"])
            .args(["--tlsv1.2", "--connect-timeout", "15", "--max-time", "150"])
            .args(["--max-filesize", "80000000", "--silent", "--show-error"])
            .arg("--output")
            .arg(&tmp)
            .arg(OSV_URL)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| "OSV_PINNED_DOWNLOAD_START_FAILED")?;
        if !status.success() {
            return Err("OSV_PINNED_DOWNLOAD_FAILED".into());
        }
        if !verified_existing(&tmp)? {
            return Err("OSV_DOWNLOADED_BINARY_MISSING".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700))
                .map_err(|_| "OSV_BOOTSTRAP_CHMOD_FAILED")?;
        }
        // Never replace an existing cache entry. Simultaneous callers can
        // independently verify the first successful install afterward.
        match fs::hard_link(&tmp, &target) {
            Ok(()) => Ok(()),
            Err(_) if target.exists() => Ok(()),
            Err(_) => Err("OSV_CACHE_ATOMIC_INSTALL_FAILED".into()),
        }
    })();
    let _ = fs::remove_file(&tmp);
    result?;
    if !verified_existing(&target)? {
        return Err("OSV_CACHE_BINARY_MISSING_AFTER_INSTALL".into());
    }
    Ok((target, OSV_SHA256))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_upstream_asset_identity_is_exact_and_https() {
        assert_eq!(OSV_SHA256.len(), 64);
        assert!(OSV_SHA256.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(
            OSV_URL.starts_with("https://github.com/google/osv-scanner/releases/download/v2.7.1/")
        );
    }
    #[test]
    fn cache_never_accepts_arbitrary_or_symlinked_bytes() {
        let directory = std::env::temp_dir().join(format!(
            "tredven-osv-bootstrap-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let sample = directory.join("fake");
        fs::write(&sample, b"not an OSV release").unwrap();
        assert_eq!(
            verified_existing(&sample).unwrap_err(),
            "OSV_CACHE_BINARY_NOT_PINNED_REGULAR_FILE"
        );
        assert!(!verified_existing(&directory.join("absent")).unwrap());
        #[cfg(unix)]
        {
            let symlink = directory.join("alias");
            std::os::unix::fs::symlink(&sample, &symlink).unwrap();
            assert_eq!(
                verified_existing(&symlink).unwrap_err(),
                "OSV_CACHE_BINARY_NOT_PINNED_REGULAR_FILE"
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
