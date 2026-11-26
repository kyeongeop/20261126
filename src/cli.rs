use std::fs;
use std::path::PathBuf;

use serde_json::json;

use crate::archive::parse_archive;
use crate::check::CheckOptions;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::fixtures::FixtureStore;
use crate::manifest::UploadManifest;
use crate::model::{ReleaseInfo, StructureReport};
use crate::report::{build_report, report_json_string};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Check,
    Scan,
    Compare,
    List,
}

#[derive(Debug)]
struct Options {
    command: Command,
    repo_root: PathBuf,
    fixtures: String,
    manifest: String,
    archive: Option<String>,
    previous: Option<String>,
    json_out: Option<PathBuf>,
    html_out: Option<PathBuf>,
    help: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            command: Command::Check,
            repo_root: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            fixtures: "fixtures".to_string(),
            manifest: "upload.json".to_string(),
            archive: None,
            previous: None,
            json_out: None,
            html_out: None,
            help: false,
        }
    }
}

/// Run the CLI and return the process exit code.
pub fn run(args: impl IntoIterator<Item = String>) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::to_string(&error.to_json()).unwrap_or_else(|_| {
                    format!(
                        "{{\"ok\":false,\"error\":{{\"code\":\"{}\"}}}}",
                        error.code.as_str()
                    )
                })
            );
            error.code.exit_code()
        }
    }
}

fn run_inner(args: impl IntoIterator<Item = String>) -> AppResult<i32> {
    let options = parse_options(args)?;
    if options.help {
        print_help();
        return Ok(0);
    }
    let store = FixtureStore::new(&options.repo_root, &options.fixtures)?;
    match options.command {
        Command::Check => check_manifest(&store, &options),
        Command::Scan => scan_archive(&store, &options),
        Command::Compare => compare_archives(&store, &options),
        Command::List => list_manifests(&store),
    }
}

fn check_manifest(store: &FixtureStore, options: &Options) -> AppResult<i32> {
    let manifest = store.read_manifest(&options.manifest)?;
    let archive_relative = manifest.archive_path.clone();
    let archive_bytes = read_archive(store, &archive_relative)?;
    let archive = parse_archive(&archive_relative, &archive_bytes)?;
    let previous = match &manifest.previous_archive_path {
        Some(path) => {
            let bytes = read_archive(store, path)?;
            Some((path.clone(), parse_archive(path, &bytes)?))
        }
        None => None,
    };
    let (previous_path, previous_archive) = match previous {
        Some((path, archive)) => (Some(path), Some(archive)),
        None => (None, None),
    };
    let report = build_report(
        &options.manifest,
        &manifest,
        &archive_relative,
        archive,
        previous_path,
        previous_archive,
        &CheckOptions::default(),
    );
    emit_report(report, options)
}

fn scan_archive(store: &FixtureStore, options: &Options) -> AppResult<i32> {
    let relative = options
        .archive
        .as_deref()
        .ok_or_else(|| AppError::new(ErrorCode::InvalidArgument, "scan requires --archive"))?;
    let bytes = read_archive(store, relative)?;
    let archive = parse_archive(relative, &bytes)?;
    let manifest = synthetic_manifest(relative, false);
    let report = build_report(
        relative,
        &manifest,
        relative,
        archive,
        None,
        None,
        &CheckOptions::default(),
    );
    emit_report(report, options)
}

fn compare_archives(store: &FixtureStore, options: &Options) -> AppResult<i32> {
    let current = options
        .archive
        .as_deref()
        .ok_or_else(|| AppError::new(ErrorCode::InvalidArgument, "compare requires --archive"))?;
    let previous = options
        .previous
        .as_deref()
        .ok_or_else(|| AppError::new(ErrorCode::InvalidArgument, "compare requires --previous"))?;
    let current_archive = parse_archive(current, &read_archive(store, current)?)?;
    let previous_archive = parse_archive(previous, &read_archive(store, previous)?)?;
    let mut manifest = synthetic_manifest(current, true);
    manifest.previous_archive_path = Some(previous.to_string());
    let report = build_report(
        current,
        &manifest,
        current,
        current_archive,
        Some(previous.to_string()),
        Some(previous_archive),
        &CheckOptions::default(),
    );
    emit_report(report, options)
}

fn list_manifests(store: &FixtureStore) -> AppResult<i32> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "fixture_root": store.fixture_root(),
            "manifests": store.list_manifests()?,
        }))
        .expect("manifest list is serializable")
    );
    Ok(0)
}

fn synthetic_manifest(path: &str, reupload: bool) -> UploadManifest {
    let name = PathBuf::from(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
        .to_string();
    UploadManifest {
        schema_version: 1,
        release: ReleaseInfo {
            name,
            version: "scan".to_string(),
            build: None,
        },
        archive_path: path.to_string(),
        archive_sha256: None,
        reupload,
        previous_archive_path: None,
        previous_archive_sha256: None,
    }
}

fn read_archive(store: &FixtureStore, relative: &str) -> AppResult<Vec<u8>> {
    store.read_bytes(relative)
}

fn emit_report(report: StructureReport, options: &Options) -> AppResult<i32> {
    if let Some(path) = &options.json_out {
        write_output(path, &report_json_string(&report))?;
    }
    if let Some(path) = &options.html_out {
        write_output(path, &crate::html::render_html(&report))?;
    }
    if options.json_out.is_none() {
        println!("{}", report_json_string(&report));
    }
    if report.verdict == crate::model::Verdict::Blocked {
        Ok(2)
    } else {
        Ok(0)
    }
}

fn write_output(path: &PathBuf, contents: &str) -> AppResult<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                AppError::new(
                    ErrorCode::OutputWriteFailed,
                    format!(
                        "cannot create output directory {}: {error}",
                        parent.display()
                    ),
                )
            })?;
        }
    }
    fs::write(path, contents).map_err(|error| {
        AppError::new(
            ErrorCode::OutputWriteFailed,
            format!("cannot write report {}: {error}", path.display()),
        )
    })
}

fn parse_options(args: impl IntoIterator<Item = String>) -> AppResult<Options> {
    let mut options = Options::default();
    let mut arguments = args.into_iter().peekable();
    if let Some(first) = arguments.peek() {
        if !first.starts_with('-') {
            options.command = match first.as_str() {
                "check" => Command::Check,
                "scan" => Command::Scan,
                "compare" => Command::Compare,
                "list" => Command::List,
                "help" => {
                    options.help = true;
                    Command::Check
                }
                other => {
                    return Err(AppError::new(
                        ErrorCode::InvalidArgument,
                        format!("unknown command {other:?}"),
                    ))
                }
            };
            arguments.next();
        }
    }
    while let Some(argument) = arguments.next() {
        if argument == "-h" || argument == "--help" {
            options.help = true;
            continue;
        }
        if !argument.starts_with("--") {
            return Err(AppError::new(
                ErrorCode::InvalidArgument,
                format!("unexpected argument {argument:?}"),
            ));
        }
        let (key, inline) = match argument.split_once('=') {
            Some((key, value)) => (key, Some(value.to_string())),
            None => (argument.as_str(), None),
        };
        let mut value = |name: &str| -> AppResult<String> {
            if let Some(value) = inline.clone() {
                return Ok(value);
            }
            arguments.next().ok_or_else(|| {
                AppError::new(
                    ErrorCode::InvalidArgument,
                    format!("{name} requires a value"),
                )
            })
        };
        match key {
            "--repo-root" => options.repo_root = PathBuf::from(value(key)?),
            "--fixtures" | "--fixture-dir" => options.fixtures = value(key)?,
            "--manifest" => options.manifest = value(key)?,
            "--archive" | "--current" => options.archive = Some(value(key)?),
            "--previous" | "--base" => options.previous = Some(value(key)?),
            "--json" | "--json-out" => options.json_out = Some(PathBuf::from(value(key)?)),
            "--html" | "--html-out" => options.html_out = Some(PathBuf::from(value(key)?)),
            other => {
                return Err(AppError::new(
                    ErrorCode::InvalidArgument,
                    format!("unknown option {other:?}"),
                ))
            }
        }
    }
    Ok(options)
}

fn print_help() {
    println!(
        r#"archive-check - release archive structure admission

USAGE
  archive-check [check] [--fixtures DIR] [--manifest FILE] [--json FILE] [--html FILE]
  archive-check scan    --fixtures DIR --archive FILE [--json FILE] [--html FILE]
  archive-check compare --fixtures DIR --archive FILE --previous FILE [--json FILE]
  archive-check list    [--fixtures DIR]

OPTIONS
  --repo-root DIR   repository root (default: current directory)
  --fixtures DIR    fixture directory below the repository root (default: fixtures)
  --manifest FILE   upload manifest below the fixture root (default: upload.json)
  --archive FILE    archive member to scan/compare
  --previous FILE   previous archive for a fixed-package re-upload
  --json FILE       write the stable JSON report
  --html FILE       write the self-contained HTML report

EXIT CODES
  0  accepted (warnings are allowed)
  2  blocked by a blocking structural finding
  1  runtime/IO/parse error
  64 command-line usage error

Only files below the fixture root are read.  Supported formats: zip, tar,
tar.gz and tgz.  Error and issue codes are stable (ARC1xxx runtime, ARC2xxx
structure, ARC3xxx re-upload comparison)."#
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_check_command() {
        let options =
            parse_options(vec!["--fixtures".to_string(), "fixtures".to_string()]).expect("options");
        assert_eq!(options.command, Command::Check);
        assert_eq!(options.fixtures, "fixtures");
    }

    #[test]
    fn rejects_unknown_option() {
        let error = parse_options(vec!["--nope".to_string()]).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }
}
