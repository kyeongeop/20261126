//! `dlr` 命令行：在发布制品管理平台中生成动态库路径风险面板。

mod analyzer;
mod config;
mod elf;
mod errors;
mod model;
mod paths;
mod report;

use analyzer::Analyzer;
use config::{PanelConfig, RepoSandbox};
use errors::{code, RiskError};
use std::path::PathBuf;
use std::process::ExitCode;

struct Cli {
    repo_root: PathBuf,
    artifact: PathBuf,
    config_path: Option<PathBuf>,
    json_out: Option<PathBuf>,
    html_out: Option<PathBuf>,
}

fn print_usage() {
    eprintln!(
        "动态库路径风险面板 (dlr)\n\n\
USAGE:\n    dlr --repo-root <DIR> --artifact <ELF> [--config <JSON>] [--json-out <FILE>] [--html-out <FILE>]\n\n\
OPTIONS:\n    --repo-root  仓库根目录，只允许分析该目录内的夹具\n    \
--artifact   根制品 ELF 路径（相对仓库根或绝对路径）\n    \
--config     允许目录等配置（JSON）\n    \
--json-out   写入 JSON 报告的路径（仍在仓库根内）\n    \
--html-out   写入 HTML 面板的路径（仍在仓库根内）\n    \
-h, --help   显示帮助"
    );
}

fn parse_args(args: Vec<String>) -> Result<Cli, RiskError> {
    let mut repo_root = None;
    let mut artifact = None;
    let mut config_path = None;
    let mut json_out = None;
    let mut html_out = None;
    let mut iter = args.into_iter().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "--repo-root" => repo_root = Some(take_value(&mut iter, "--repo-root")?),
            "--artifact" => artifact = Some(take_value(&mut iter, "--artifact")?),
            "--config" => config_path = Some(take_value(&mut iter, "--config")?),
            "--json-out" => json_out = Some(take_value(&mut iter, "--json-out")?),
            "--html-out" => html_out = Some(take_value(&mut iter, "--html-out")?),
            other => {
                return Err(RiskError::new(
                    code::INVALID_ARGUMENT,
                    format!("未知参数 {other}"),
                ))
            }
        }
    }
    Ok(Cli {
        repo_root: repo_root.ok_or_else(|| {
            RiskError::new(code::INVALID_ARGUMENT, "缺少必填参数 --repo-root")
        })?,
        artifact: artifact.ok_or_else(|| {
            RiskError::new(code::INVALID_ARGUMENT, "缺少必填参数 --artifact")
        })?,
        config_path,
        json_out,
        html_out,
    })
}

fn take_value(
    iter: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<PathBuf, RiskError> {
    iter.next()
        .map(PathBuf::from)
        .ok_or_else(|| RiskError::new(code::INVALID_ARGUMENT, format!("参数 {flag} 缺少值")))
}

fn run() -> Result<(), RiskError> {
    let cli = parse_args(std::env::args().collect())?;
    let sandbox = RepoSandbox::new(&cli.repo_root)?;
    let config = match &cli.config_path {
        Some(path) => PanelConfig::load(&sandbox.resolve(path)?)?,
        None => PanelConfig::default(),
    };

    let analyzer = Analyzer::new(&sandbox, &config);
    let panel = analyzer.run(&cli.artifact)?;

    let json = report::to_json(&panel)?;
    if let Some(out) = &cli.json_out {
        std::fs::write(&sandbox.resolve_output(out)?, json.as_bytes())?;
    } else {
        println!("{json}");
    }
    if let Some(out) = &cli.html_out {
        let html = report::to_html(&panel);
        std::fs::write(&sandbox.resolve_output(out)?, html.as_bytes())?;
    }

    let s = &panel.summary;
    eprintln!(
        "扫描完成：制品 {} 个，依赖 {} 条，风险 {} 条（严重 {} / 高 {} / 中 {} / 低 {}），缺失依赖 {}",
        s.artifact_count,
        s.edge_count,
        s.finding_count,
        s.critical,
        s.high,
        s.medium,
        s.low,
        s.missing_dependencies
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", report::error_json(&error));
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}
