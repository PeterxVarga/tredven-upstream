use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use tredven_upstream::{
    Decision, PreflightInput, PreflightReport, contract::inspect_open_seo_0049,
    git_source::inspect_local_git, inspect, to_markdown,
};

const MAX_INPUT_BYTES: u64 = 1024 * 1024;

fn usage() -> &'static str {
    "Tredven Upstream — local read-only upgrade evidence\n\
     Usage: tredven-upstream inspect --input FILE|--stdin [--format json|markdown]\n\
     Usage: tredven-upstream inspect-git --repo DIR --project ID --from TAG --to TAG [--format json|markdown]\n\
     Usage: tredven-upstream inspect-contract --repo DIR --project open-seo --profile open-seo-v0.1.31-stripe-projects-0049 [--schema-snapshot FILE] [--format json|markdown]\n\
     Git inspection is local only, never a remote release or production attestation.\n\
     No network, Docker, provider credentials, mutations or deploy permissions.\n"
}

fn fail(message: &str) -> ExitCode {
    eprintln!("ERROR: {message}");
    ExitCode::from(1)
}

fn emit(report: &PreflightReport, format: &str) -> Result<u8, String> {
    if !["json", "markdown"].contains(&format) {
        return Err("UNSUPPORTED_FORMAT".into());
    }
    let mut stdout = io::stdout().lock();
    if format == "json" {
        serde_json::to_writer_pretty(&mut stdout, report).map_err(|_| "JSON_OUTPUT_FAILED")?;
        writeln!(&mut stdout).map_err(|_| "STDOUT_WRITE_FAILED")?;
    } else {
        write!(&mut stdout, "{}", to_markdown(report)).map_err(|_| "STDOUT_WRITE_FAILED")?;
    }
    Ok(if report.decision == Decision::Blocked {
        2
    } else {
        0
    })
}

fn run_git(mut args: impl Iterator<Item = String>) -> Result<u8, String> {
    let (mut repo, mut project, mut from, mut to) = (None, None, None, None);
    let mut format = "json".to_owned();
    while let Some(arg) = args.next() {
        let value = match arg.as_str() {
            "--help" | "-h" => {
                print!("{}", usage());
                return Ok(0);
            }
            "--repo" | "--project" | "--from" | "--to" | "--format" => {
                args.next().ok_or("MISSING_GIT_ARGUMENT_VALUE")?
            }
            _ => return Err("UNRECOGNIZED_GIT_ARGUMENT".into()),
        };
        let target = match arg.as_str() {
            "--repo" => &mut repo,
            "--project" => &mut project,
            "--from" => &mut from,
            "--to" => &mut to,
            _ => {
                if format != "json" {
                    return Err("FORMAT_SPECIFIED_MORE_THAN_ONCE".into());
                }
                format = value;
                continue;
            }
        };
        if target.replace(value).is_some() {
            return Err("GIT_ARGUMENT_SPECIFIED_MORE_THAN_ONCE".into());
        }
    }
    let repo = repo.ok_or("MISSING_GIT_REPO")?;
    let project = project.ok_or("MISSING_GIT_PROJECT")?;
    let from = from.ok_or("MISSING_GIT_FROM_TAG")?;
    let to = to.ok_or("MISSING_GIT_TO_TAG")?;
    let report = inspect_local_git(Path::new(&repo), &project, &from, &to)?;
    emit(&report, &format)
}

fn run_contract(mut args: impl Iterator<Item = String>) -> Result<u8, String> {
    let (mut repo, mut project, mut profile, mut schema) = (None, None, None, None);
    let mut format = "json".to_owned();
    while let Some(arg) = args.next() {
        let value = match arg.as_str() {
            "--help" | "-h" => {
                print!("{}", usage());
                return Ok(0);
            }
            "--repo" | "--project" | "--profile" | "--schema-snapshot" | "--format" => {
                args.next().ok_or("MISSING_CONTRACT_ARGUMENT_VALUE")?
            }
            _ => return Err("UNRECOGNIZED_CONTRACT_ARGUMENT".into()),
        };
        let slot = match arg.as_str() {
            "--repo" => &mut repo,
            "--project" => &mut project,
            "--profile" => &mut profile,
            "--schema-snapshot" => &mut schema,
            "--format" => {
                format = value;
                continue;
            }
            _ => unreachable!(),
        };
        if slot.replace(value).is_some() {
            return Err("CONTRACT_ARGUMENT_SPECIFIED_MORE_THAN_ONCE".into());
        }
    }
    let repo = repo.ok_or("MISSING_CONTRACT_GIT_REPO")?;
    let project = project.ok_or("MISSING_CONTRACT_PROJECT")?;
    let profile = profile.ok_or("MISSING_CONTRACT_PROFILE")?;
    let report = inspect_open_seo_0049(
        Path::new(&repo),
        &project,
        &profile,
        schema.as_deref().map(Path::new),
    )?;
    emit(&report, &format)
}

fn run() -> Result<u8, String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--help" | "-h") => {
            print!("{}", usage());
            return Ok(0);
        }
        Some("inspect") => {}
        Some("inspect-git") => return run_git(args),
        Some("inspect-contract") => return run_contract(args),
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
    emit(&report, &format)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(message) => fail(&message),
    }
}
