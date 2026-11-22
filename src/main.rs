use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use tredven_upstream::{Decision, PreflightInput, inspect, to_markdown};

const MAX_INPUT_BYTES: u64 = 1024 * 1024;

fn usage() -> &'static str {
    "Tredven Upstream — local read-only upgrade evidence\n\
     Usage: tredven-upstream inspect --input FILE|--stdin [--format json|markdown]\n\
     No network, Docker, provider credentials, mutations or deploy permissions.\n"
}

fn fail(message: &str) -> ExitCode {
    eprintln!("ERROR: {message}");
    ExitCode::from(1)
}

fn run() -> Result<u8, String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--help" | "-h") => {
            print!("{}", usage());
            return Ok(0);
        }
        Some("inspect") => {}
        _ => return Err(usage().trim_end().into()),
    };

    let mut input_path = None;
    let mut from_stdin = false;
    let mut format = "json".to_owned();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => {
                if input_path.is_some() || from_stdin {
                    return Err("INPUT_SPECIFIED_MORE_THAN_ONCE".into());
                }
                input_path = Some(args.next().ok_or("MISSING_INPUT_PATH")?);
            }
            "--stdin" => {
                if input_path.is_some() || from_stdin {
                    return Err("INPUT_SPECIFIED_MORE_THAN_ONCE".into());
                }
                from_stdin = true;
            }
            "--format" => format = args.next().ok_or("MISSING_FORMAT")?,
            "--help" | "-h" => {
                print!("{}", usage());
                return Ok(0);
            }
            _ => return Err("UNRECOGNIZED_ARGUMENT".into()),
        }
    }
    if !["json", "markdown"].contains(&format.as_str()) {
        return Err("UNSUPPORTED_FORMAT".into());
    }

    let input = if let Some(path) = input_path {
        let path = Path::new(&path);
        let metadata = fs::symlink_metadata(path).map_err(|_| "INPUT_FILE_UNAVAILABLE")?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_INPUT_BYTES {
            return Err("INPUT_MUST_BE_BOUNDED_REGULAR_FILE".into());
        }
        fs::read_to_string(path).map_err(|_| "INPUT_FILE_READ_FAILED")?
    } else if from_stdin {
        let mut bytes = Vec::new();
        io::stdin()
            .take(MAX_INPUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "STDIN_READ_FAILED")?;
        if bytes.len() as u64 > MAX_INPUT_BYTES {
            return Err("INPUT_TOO_LARGE".into());
        }
        String::from_utf8(bytes).map_err(|_| "INPUT_NOT_UTF8")?
    } else {
        return Err("MISSING_INPUT".into());
    };

    let request: PreflightInput = serde_json::from_str(&input).map_err(|_| "INVALID_INPUT_JSON")?;
    let report = inspect(request)?;
    let mut stdout = io::stdout().lock();
    if format == "json" {
        serde_json::to_writer_pretty(&mut stdout, &report).map_err(|_| "JSON_OUTPUT_FAILED")?;
        writeln!(&mut stdout).map_err(|_| "STDOUT_WRITE_FAILED")?;
    } else {
        write!(&mut stdout, "{}", to_markdown(&report)).map_err(|_| "STDOUT_WRITE_FAILED")?;
    }
    Ok(if report.decision == Decision::Blocked {
        2
    } else {
        0
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(message) => fail(&message),
    }
}
