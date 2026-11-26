//! Release manifest loading. The parser is tolerant of a few key aliases so
//! both platform exports and hand-written JSON work.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::codes;

#[derive(Debug, Clone)]
pub struct ManifestTarget {
    pub path: String,
    pub required: bool,
    pub required_symbols: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub name: Option<String>,
    pub version: Option<String>,
    /// Directory used to resolve relative target paths.
    pub base_dir: PathBuf,
    pub targets: Vec<ManifestTarget>,
}

#[derive(Debug, Clone)]
pub struct ManifestError {
    pub code: &'static str,
    pub message: String,
}

impl ManifestError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        ManifestError {
            code,
            message: message.into(),
        }
    }
}

fn as_string(value: &Value) -> Option<String> {
    value.as_str().map(|s| s.to_string())
}

fn pick<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| value.get(*key))
}

fn parse_target(value: &Value) -> Option<ManifestTarget> {
    if let Some(path) = value.as_str() {
        return Some(ManifestTarget {
            path: path.to_string(),
            required: true,
            required_symbols: Vec::new(),
        });
    }
    let path_value = pick(value, &["path", "file", "filename", "artifact", "location"])?;
    let path = path_value.as_str()?.to_string();

    let required = pick(value, &["required", "mandatory", "gate"])
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let required_symbols = pick(value, &["required_symbols", "require_symbols", "symbols"])
        .map(parse_string_list)
        .unwrap_or_default();

    Some(ManifestTarget {
        path,
        required,
        required_symbols,
    })
}

fn parse_string_list(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(|item| match item {
                Value::String(s) => Some(s.clone()),
                other => other.as_str().map(str::to_string),
            })
            .collect(),
        Value::String(s) => s
            .split(',')
            .map(|part| part.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

pub fn parse_manifest(text: &str, base_dir: PathBuf) -> Result<Manifest, ManifestError> {
    let root: Value = serde_json::from_str(text)
        .map_err(|err| ManifestError::new(codes::E_MANIFEST_PARSE, err.to_string()))?;

    let release = root.get("release");
    let name = release
        .and_then(|r| pick(r, &["name", "product", "app"]))
        .and_then(as_string)
        .or_else(|| pick(&root, &["name", "product"]).and_then(as_string));
    let version = release
        .and_then(|r| pick(r, &["version", "ver"]))
        .and_then(as_string)
        .or_else(|| pick(&root, &["version"]).and_then(as_string));

    let mut resolved_base = base_dir;
    if let Some(root_dir) =
        pick(&root, &["root", "artifact_root", "base_dir", "directory"]).and_then(Value::as_str)
    {
        let candidate = PathBuf::from(root_dir);
        resolved_base = if candidate.is_absolute() {
            candidate
        } else {
            resolved_base.join(candidate)
        };
    }

    let targets_value = pick(&root, &["targets", "artifacts", "files", "binaries"]);
    let mut targets = Vec::new();
    if let Some(Value::Array(items)) = targets_value {
        for item in items {
            if let Some(target) = parse_target(item) {
                targets.push(target);
            }
        }
    }

    Ok(Manifest {
        name,
        version,
        base_dir: resolved_base,
        targets,
    })
}

pub fn load_manifest(path: &Path) -> Result<Manifest, ManifestError> {
    let text = std::fs::read_to_string(path).map_err(|err| {
        ManifestError::new(codes::E_MANIFEST_READ, format!("{}: {err}", path.display()))
    })?;
    let base_dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    parse_manifest(&text, base_dir)
}
