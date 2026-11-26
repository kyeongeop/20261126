//! Build gate reports from files, directories or a release manifest.

use std::path::{Path, PathBuf};

use crate::artifact::inspect_path;
use crate::gate::evaluate_target;
use crate::manifest::{load_manifest, Manifest};
use crate::model::TargetType;
use crate::report::{current_unix_secs, summarize, ArtifactReport, GateReport};

pub fn report_from_path(
    path: &Path,
    required: bool,
    required_symbols: Vec<String>,
) -> ArtifactReport {
    let inspected = inspect_path(path, None, required, required_symbols);
    let evaluation = evaluate_target(&inspected);
    ArtifactReport {
        inspected,
        evaluation,
    }
}

fn finalize(
    source_kind: &str,
    source: &str,
    release_name: Option<String>,
    release_version: Option<String>,
    mut artifacts: Vec<ArtifactReport>,
    ignored_files: Vec<String>,
) -> GateReport {
    artifacts.sort_by(|left, right| {
        left.inspected
            .display_path
            .cmp(&right.inspected.display_path)
    });
    let summary = summarize(&artifacts);
    GateReport {
        source_kind: source_kind.to_string(),
        source: source.to_string(),
        release_name,
        release_version,
        generated_unix_secs: current_unix_secs(),
        artifacts,
        ignored_files,
        summary,
    }
}

/// Build a report from a release manifest.
pub fn build_from_manifest(manifest: &Manifest, source: &str) -> GateReport {
    let mut artifacts = Vec::new();
    for target in &manifest.targets {
        let resolved = if Path::new(&target.path).is_absolute() {
            PathBuf::from(&target.path)
        } else {
            manifest.base_dir.join(&target.path)
        };
        let mut report =
            report_from_path(&resolved, target.required, target.required_symbols.clone());
        // Prefer the manifest-declared relative path for stable listing.
        report.inspected.display_path = target.path.clone();
        artifacts.push(report);
    }
    finalize(
        "manifest",
        source,
        manifest.name.clone(),
        manifest.version.clone(),
        artifacts,
        Vec::new(),
    )
}

// Only VCS metadata is skipped. Build/dependency directories such as
// `target/` or `vendor/` are still scanned if the caller points us at them:
// a release gate must not silently omit a directory of artifacts.
const PRUNED_DIRS: &[&str] = &[".git"];

fn walk_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            let pruned = path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| PRUNED_DIRS.contains(&name))
                .unwrap_or(false);
            if !pruned {
                walk_files(&path, out);
            }
        } else if file_type.is_file() || file_type.is_symlink() {
            out.push(path);
        }
    }
}

/// Recursively scan a directory. Recognized object/archive files become
/// required targets; other files are recorded as ignored.
pub fn scan_directory(root: &Path) -> GateReport {
    let mut files = Vec::new();
    walk_files(root, &mut files);
    files.sort();

    let mut artifacts = Vec::new();
    let mut ignored = Vec::new();
    for file in files {
        let report = report_from_path(&file, true, Vec::new());
        if report.inspected.target_type == TargetType::Other {
            ignored.push(report.inspected.display_path.clone());
        } else {
            artifacts.push(report);
        }
    }

    finalize(
        "directory",
        &root.to_string_lossy(),
        None,
        None,
        artifacts,
        ignored,
    )
}

/// Inspect exactly one path as a required target.
pub fn inspect_single(path: &Path, required_symbols: Vec<String>) -> GateReport {
    let report = report_from_path(path, true, required_symbols);
    finalize(
        "file",
        &path.to_string_lossy(),
        None,
        None,
        vec![report],
        Vec::new(),
    )
}

/// Inspect an explicit list of file paths as required targets.
pub fn build_from_paths(paths: &[PathBuf]) -> GateReport {
    let artifacts = paths
        .iter()
        .map(|path| report_from_path(path, true, Vec::new()))
        .collect();
    let source = paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    finalize("paths", &source, None, None, artifacts, Vec::new())
}

/// Flexible high-level entry point used by both the CLI and tests:
/// - directory path  -> recursive scan
/// - `.json` file    -> release manifest
/// - any other file  -> single required target
pub fn evaluate_path(path: &Path) -> Result<GateReport, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|err| format!("{}: {err}", crate::codes::E_PATH_NOT_FOUND))?;
    if metadata.is_dir() {
        return Ok(scan_directory(path));
    }
    let is_manifest = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    if is_manifest {
        let manifest =
            load_manifest(path).map_err(|err| format!("{}: {}", err.code, err.message))?;
        return Ok(build_from_manifest(&manifest, &path.to_string_lossy()));
    }
    Ok(inspect_single(path, Vec::new()))
}
