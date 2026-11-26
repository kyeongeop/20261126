use serde_json::{Map, Value};

use crate::digest::normalize_sha256;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::model::ReleaseInfo;

/// Parsed upload manifest.  Relative archive paths are resolved by the
/// fixture store, never against the process working directory.
#[derive(Debug, Clone)]
pub struct UploadManifest {
    pub schema_version: u64,
    pub release: ReleaseInfo,
    pub archive_path: String,
    pub archive_sha256: Option<String>,
    pub reupload: bool,
    pub previous_archive_path: Option<String>,
    pub previous_archive_sha256: Option<String>,
}

impl UploadManifest {
    pub fn from_json_str(text: &str) -> AppResult<Self> {
        let value: Value = serde_json::from_str(text).map_err(|error| {
            AppError::new(
                ErrorCode::ManifestJsonInvalid,
                format!("upload manifest is not valid JSON: {error}"),
            )
        })?;
        Self::from_value(&value)
    }

    pub fn from_value(value: &Value) -> AppResult<Self> {
        let map = value.as_object().ok_or_else(|| {
            AppError::new(
                ErrorCode::ManifestSchemaInvalid,
                "upload manifest must be a JSON object",
            )
        })?;
        let schema_version = match map.get("schema_version") {
            None => 1,
            Some(Value::Number(number)) => number
                .as_u64()
                .ok_or_else(|| schema_error("schema_version must be a positive integer"))?,
            Some(_) => return Err(schema_error("schema_version must be an integer")),
        };
        if schema_version != 1 {
            return Err(schema_error(format!(
                "unsupported manifest schema_version {schema_version}"
            )));
        }

        let release_map = map
            .get("release")
            .and_then(Value::as_object)
            .ok_or_else(|| schema_error("release must be an object"))?;
        let release = ReleaseInfo {
            name: required_string(release_map, &["name", "project"], "release.name")?,
            version: required_string(release_map, &["version", "tag"], "release.version")?,
            build: optional_string(release_map, &["build", "build_id"], "release.build")?,
        };

        let archive_ref = map
            .get("archive")
            .or_else(|| map.get("package"))
            .or_else(|| map.get("artifact"));
        let (archive_path, archive_sha256) = match archive_ref {
            Some(value) => parse_artifact_ref(value, "archive")?,
            None => (
                optional_string(map, &["archive_path", "package_path"], "archive_path")?
                    .ok_or_else(|| schema_error("archive is required"))?,
                optional_string(
                    map,
                    &["archive_sha256", "artifact_sha256"],
                    "archive_sha256",
                )?
                .map(|value| normalize_digest(&value, "archive_sha256"))
                .transpose()?,
            ),
        };
        if archive_path.trim().is_empty() {
            return Err(schema_error("archive.path must not be empty"));
        }

        let previous_ref = map
            .get("previous")
            .or_else(|| map.get("previous_archive"))
            .or_else(|| map.get("base"));
        let (previous_archive_path, previous_archive_sha256) = match previous_ref {
            Some(value) => {
                let (path, digest) = parse_artifact_ref(value, "previous")?;
                let path = if path.is_empty() {
                    optional_string(map, &["previous_archive_path"], "previous_archive_path")?
                } else {
                    Some(path)
                };
                (path, digest)
            }
            None => (
                optional_string(
                    map,
                    &["previous_archive_path", "base_archive"],
                    "previous_archive_path",
                )?,
                optional_string(
                    map,
                    &["previous_archive_sha256", "previous_sha256"],
                    "previous_archive_sha256",
                )?
                .map(|value| normalize_digest(&value, "previous_archive_sha256"))
                .transpose()?,
            ),
        };
        let previous_archive_path = previous_archive_path.filter(|path| !path.trim().is_empty());
        let upload_kind = optional_string(map, &["upload_type", "kind"], "upload_type")?
            .unwrap_or_default()
            .to_ascii_lowercase();
        let reupload = optional_bool(map, &["reupload", "is_fix"], "reupload")?.unwrap_or(false)
            || matches!(upload_kind.as_str(), "fix" | "reupload" | "fixed");
        if reupload && previous_archive_path.is_none() {
            return Err(AppError::new(
                ErrorCode::PreviousArchiveRequired,
                "a fix/re-upload manifest must declare the previous archive",
            ));
        }

        Ok(Self {
            schema_version,
            release,
            archive_path,
            archive_sha256,
            reupload,
            previous_archive_path,
            previous_archive_sha256,
        })
    }
}

fn parse_artifact_ref(value: &Value, path: &str) -> AppResult<(String, Option<String>)> {
    match value {
        Value::String(path_value) => Ok((path_value.clone(), None)),
        Value::Object(map) => {
            let path_value = optional_string(map, &["path", "file"], path)?
                .ok_or_else(|| schema_error(format!("{path}.path is required")))?;
            let digest = optional_string(map, &["sha256", "digest"], path)?
                .map(|value| normalize_digest(&value, path))
                .transpose()?;
            Ok((path_value, digest))
        }
        _ => Err(schema_error(format!(
            "{path} must be a path string or an object"
        ))),
    }
}

fn normalize_digest(value: &str, path: &str) -> AppResult<String> {
    normalize_sha256(value).ok_or_else(|| {
        AppError::at_path(
            ErrorCode::ManifestSchemaInvalid,
            path,
            "expected 64 hexadecimal SHA-256 characters",
        )
    })
}

fn required_string(map: &Map<String, Value>, keys: &[&str], path: &str) -> AppResult<String> {
    optional_string(map, keys, path)?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| schema_error(format!("{path} is required")))
}

fn optional_string(
    map: &Map<String, Value>,
    keys: &[&str],
    path: &str,
) -> AppResult<Option<String>> {
    for key in keys {
        match map.get(*key) {
            Some(Value::String(value)) => return Ok(Some(value.trim().to_string())),
            Some(Value::Null) | None => {}
            Some(_) => {
                return Err(AppError::at_path(
                    ErrorCode::ManifestSchemaInvalid,
                    format!("{path}.{key}"),
                    "expected a string",
                ))
            }
        }
    }
    Ok(None)
}

fn optional_bool(map: &Map<String, Value>, keys: &[&str], path: &str) -> AppResult<Option<bool>> {
    for key in keys {
        match map.get(*key) {
            Some(Value::Bool(value)) => return Ok(Some(*value)),
            Some(Value::Null) | None => {}
            Some(_) => {
                return Err(AppError::at_path(
                    ErrorCode::ManifestSchemaInvalid,
                    format!("{path}.{key}"),
                    "expected a boolean",
                ))
            }
        }
    }
    Ok(None)
}

fn schema_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ManifestSchemaInvalid, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_object_archive_and_previous() {
        let manifest = UploadManifest::from_json_str(
            r#"{
                "release": {"name": "demo", "version": "1.0.0"},
                "archive": {"path": "archives/current.zip", "sha256": "aaaa"},
                "reupload": true,
                "previous": {"path": "archives/previous.zip"}
            }"#,
        );
        assert!(manifest.is_err(), "short digest must be rejected");
    }

    #[test]
    fn parses_top_level_archive_path_alias() {
        let digest = "a".repeat(64);
        let manifest = UploadManifest::from_json_str(&format!(
            r#"{{
                "release": {{"name": "demo", "version": "1.0.0"}},
                "archive_path": "archives/current.zip",
                "archive_sha256": "{digest}"
            }}"#
        ))
        .expect("manifest");
        assert_eq!(manifest.archive_path, "archives/current.zip");
        assert_eq!(manifest.archive_sha256.as_deref(), Some(digest.as_str()));
    }

    #[test]
    fn requires_previous_for_fix_upload() {
        let error = UploadManifest::from_json_str(
            r#"{
                "release": {"name": "demo", "version": "1.0.1"},
                "archive": "archives/fix.zip",
                "upload_type": "fix"
            }"#,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::PreviousArchiveRequired);
    }
}
