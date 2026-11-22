use std::path::PathBuf;
use std::process::{Command, Stdio};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

fn invoke(name: &str, format: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tredven-upstream"))
        .args(["inspect", "--input"])
        .arg(fixture(name))
        .args(["--format", format])
        .output()
        .expect("CLI starts")
}

#[test]
fn live_cli_json_review_is_not_release_approval() {
    let output = invoke("upgrade-review.json", "json");
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["decision"], "REVIEW");
    assert_eq!(report["compare_coverage"], "complete");
    assert_eq!(report["authority"]["release"], false);
    assert_eq!(report["production_ready"], false);
}

#[test]
fn live_cli_json_blocked_returns_exit_two() {
    let output = invoke("upgrade-blocked.json", "json");
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["decision"], "BLOCKED");
    assert_eq!(report["authority"]["send"], false);
}

#[test]
fn live_cli_unknown_is_not_an_empty_success() {
    let output = invoke("upgrade-unknown.json", "json");
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["decision"], "UNKNOWN");
    assert_eq!(report["source_changed"], serde_json::Value::Null);
}

#[test]
fn cli_markdown_contains_next_action() {
    let output = invoke("upgrade-review.json", "markdown");
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("MIGRATION_OR_SCHEMA"));
    assert!(text.contains("No deployment, patch, merge"));
}

#[test]
fn stdin_is_bounded_and_supported() {
    use std::io::Write;
    let fixture = std::fs::read(fixture("upgrade-unknown.json")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"))
        .args(["inspect", "--stdin", "--format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&fixture).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("UNKNOWN")
    );
}

#[test]
fn symlink_input_is_denied() {
    #[cfg(unix)]
    {
        let temp =
            std::env::temp_dir().join(format!("tredven-upstream-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&temp);
        std::os::unix::fs::symlink(fixture("upgrade-review.json"), &temp).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_tredven-upstream"))
            .args(["inspect", "--input"])
            .arg(&temp)
            .output()
            .unwrap();
        std::fs::remove_file(&temp).unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("BOUNDED_REGULAR")
        );
    }
}
