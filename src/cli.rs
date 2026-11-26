//! Command-line interface exposed as a library for in-process tests.

use std::path::PathBuf;

use crate::codes;
use crate::html::render_html;
use crate::manifest::load_manifest;
use crate::report::GateReport;
use crate::scan::{build_from_manifest, build_from_paths, evaluate_path, scan_directory};

pub const HELP: &str = "\
hardening-gate — 多目标加固门禁 / multi-target hardening gate

Checks PIE, NX, RELRO, BIND_NOW and symbol evidence for executables, shared
libraries (.so) and static archives (.a). Indeterminate results are `unknown`.
A required target blocks the release when any required check is fail/unknown.

USAGE:
    hardening-gate [OPTIONS] [PATH ...]

ARGS:
    <PATH>...   File, directory, or release manifest (.json). With no PATH the
                tool uses fixtures/release.json, then the fixtures/ directory.

OPTIONS:
    -m, --manifest <FILE>   Load targets from a release manifest JSON.
    -d, --dir <DIR>         Recursively scan a directory of artifacts.
        --json <FILE>       Write the JSON report (default: release-gate.json).
        --html <FILE>       Write the HTML page (default: release-gate.html).
        --no-write          Do not write JSON/HTML files.
        --print-json        Print the JSON report to stdout.
    -q, --quiet             Print only the final decision line.
    -h, --help              Show this help.
    -V, --version           Show version.

EXIT CODES:
    0  gate passed (GATE_PASSED)
    1  runtime/IO error (E_PATH_NOT_FOUND, E_MANIFEST_*, E_REPORT_WRITE, ...)
    2  release blocked (GATE_BLOCKED)
    64 invalid usage (E_USAGE)
";

#[derive(Debug, Default)]
pub struct Cli {
    pub manifest: Option<PathBuf>,
    pub dir: Option<PathBuf>,
    pub json_out: Option<PathBuf>,
    pub html_out: Option<PathBuf>,
    pub no_write: bool,
    pub print_json: bool,
    pub quiet: bool,
    pub positionals: Vec<PathBuf>,
    pub show_help: bool,
    pub show_version: bool,
}

pub fn parse_args<I, S>(args: I) -> Result<Cli, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut cli = Cli::default();
    let mut iter = args.into_iter().map(Into::into);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => cli.show_help = true,
            "-V" | "--version" => cli.show_version = true,
            "-q" | "--quiet" => cli.quiet = true,
            "--no-write" => cli.no_write = true,
            "--print-json" => cli.print_json = true,
            "-m" | "--manifest" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{}: --manifest requires a file", codes::E_USAGE))?;
                cli.manifest = Some(PathBuf::from(value));
            }
            "-d" | "--dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{}: --dir requires a directory", codes::E_USAGE))?;
                cli.dir = Some(PathBuf::from(value));
            }
            "--json" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{}: --json requires a path", codes::E_USAGE))?;
                cli.json_out = Some(PathBuf::from(value));
            }
            "--html" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{}: --html requires a path", codes::E_USAGE))?;
                cli.html_out = Some(PathBuf::from(value));
            }
            other if other.starts_with("--manifest=") => {
                cli.manifest = Some(PathBuf::from(&other["--manifest=".len()..]));
            }
            other if other.starts_with("--json=") => {
                cli.json_out = Some(PathBuf::from(&other["--json=".len()..]));
            }
            other if other.starts_with("--html=") => {
                cli.html_out = Some(PathBuf::from(&other["--html=".len()..]));
            }
            flag if flag.starts_with('-') && flag.len() > 1 => {
                return Err(format!("{}: unknown option '{flag}'", codes::E_USAGE));
            }
            positional => cli.positionals.push(PathBuf::from(positional)),
        }
    }
    Ok(cli)
}

pub fn default_report() -> GateReport {
    let manifest_path = PathBuf::from("fixtures/release.json");
    if manifest_path.is_file() {
        if let Ok(manifest) = load_manifest(&manifest_path) {
            return build_from_manifest(&manifest, &manifest_path.to_string_lossy());
        }
    }
    scan_directory(&PathBuf::from("fixtures"))
}

fn execute(cli: &Cli) -> Result<i32, String> {
    let report = if let Some(manifest_path) = &cli.manifest {
        let manifest =
            load_manifest(manifest_path).map_err(|err| format!("{}: {}", err.code, err.message))?;
        build_from_manifest(&manifest, &manifest_path.to_string_lossy())
    } else if let Some(dir) = &cli.dir {
        scan_directory(dir)
    } else if cli.positionals.is_empty() {
        default_report()
    } else if cli.positionals.len() == 1 {
        evaluate_path(&cli.positionals[0])?
    } else {
        build_from_paths(&cli.positionals)
    };

    let json_text = report.to_json_string_pretty();
    let html_text = render_html(&report);

    if cli.print_json {
        println!("{json_text}");
    }

    if !cli.no_write {
        let json_path = cli
            .json_out
            .clone()
            .unwrap_or_else(|| PathBuf::from("release-gate.json"));
        let html_path = cli
            .html_out
            .clone()
            .unwrap_or_else(|| PathBuf::from("release-gate.html"));
        if let Some(parent) = json_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("{}: {e}", codes::E_REPORT_WRITE))?;
        }
        if let Some(parent) = html_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("{}: {e}", codes::E_REPORT_WRITE))?;
        }
        std::fs::write(&json_path, json_text.as_bytes())
            .map_err(|e| format!("{} {}: {e}", codes::E_REPORT_WRITE, json_path.display()))?;
        std::fs::write(&html_path, html_text.as_bytes())
            .map_err(|e| format!("{} {}: {e}", codes::E_REPORT_WRITE, html_path.display()))?;
        if !cli.quiet {
            eprintln!("JSON report: {}", json_path.display());
            eprintln!("HTML page:   {}", html_path.display());
        }
    }

    let summary = &report.summary;
    if !cli.quiet {
        eprintln!(
            "gate={} targets={} required={} pass={} fail={} unknown={} blocking=[{}]",
            summary.decision,
            summary.total_targets,
            summary.required_targets,
            summary.passed,
            summary.failed,
            summary.unknown,
            summary.blocking_targets.join(", ")
        );
    } else {
        println!("{}", summary.decision);
    }
    Ok(summary.exit_code)
}

/// Run the CLI for an argument list WITHOUT the executable name.
/// Returns the process exit code.
pub fn run_with_args<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let cli = match parse_args(args) {
        Ok(cli) => cli,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("run `hardening-gate --help` for usage");
            return codes::EXIT_USAGE;
        }
    };
    if cli.show_help {
        print!("{HELP}");
        return codes::EXIT_PASS;
    }
    if cli.show_version {
        println!("hardening-gate {}", env!("CARGO_PKG_VERSION"));
        return codes::EXIT_PASS;
    }
    match execute(&cli) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            codes::EXIT_RUNTIME_ERROR
        }
    }
}
