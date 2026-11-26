use crate::error::{
    AdmissionError, Result, E_ARTIFACT_IO, E_INVALID_ARTIFACT_DIGEST, E_INVALID_FIELD,
};
use object::Object;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Structural metadata extracted from a release object when available.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectMetadata {
    pub format: String,
    pub architecture: String,
    pub is_64_bit: bool,
    pub is_little_endian: bool,
}

/// A release artifact bound to its SHA-256 digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    pub sha256: String,
    pub size: Option<u64>,
    pub object: Option<ObjectMetadata>,
}

impl Artifact {
    /// Hash bytes with SHA-256 and inspect them as an object file when possible.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let object = object::File::parse(bytes).ok().map(|file| ObjectMetadata {
            format: format!("{:?}", file.format()).to_ascii_lowercase(),
            architecture: format!("{:?}", file.architecture()).to_ascii_lowercase(),
            is_64_bit: file.is_64(),
            is_little_endian: file.is_little_endian(),
        });
        Self {
            sha256: hex_sha256(bytes),
            size: Some(bytes.len() as u64),
            object,
        }
    }

    /// Read an artifact from a repository fixture path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|error| {
            AdmissionError::new(
                E_ARTIFACT_IO,
                format!("cannot read artifact {}: {error}", path.display()),
            )
        })?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Build an artifact descriptor from a declared SHA-256 digest.
    pub fn from_sha256(digest: &str) -> Result<Self> {
        Ok(Self {
            sha256: normalize_sha256(digest)?,
            size: None,
            object: None,
        })
    }

    pub fn matches(&self, other_digest: &str) -> bool {
        normalize_sha256(other_digest)
            .map(|digest| digest == self.sha256)
            .unwrap_or(false)
    }

    pub fn to_json(&self) -> Value {
        let object = self.object.as_ref().map(|metadata| {
            json!({
                "format": metadata.format,
                "architecture": metadata.architecture,
                "is_64_bit": metadata.is_64_bit,
                "is_little_endian": metadata.is_little_endian,
            })
        });
        json!({
            "sha256": self.sha256,
            "size": self.size,
            "object": object,
        })
    }

    pub(crate) fn from_json(value: &Value, path: &str) -> Result<Self> {
        match value {
            Value::String(digest) => Self::from_sha256(digest),
            Value::Object(map) => {
                let declared = map
                    .get("sha256")
                    .or_else(|| map.get("digest"))
                    .or_else(|| map.get("artifact_sha256"));
                let declared = match declared {
                    Some(Value::String(digest)) => Some(normalize_sha256(digest)?),
                    Some(_) => {
                        return Err(AdmissionError::at_path(
                            E_INVALID_FIELD,
                            format!("{path}.sha256"),
                            "expected a SHA-256 hex string",
                        ))
                    }
                    None => None,
                };

                let file_path = match map.get("path") {
                    Some(Value::String(path)) => Some(path.as_str()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(AdmissionError::at_path(
                            E_INVALID_FIELD,
                            format!("{path}.path"),
                            "expected a fixture path string",
                        ))
                    }
                };
                if let Some(file_path) = file_path {
                    let mut artifact = Self::from_path(file_path)?;
                    if let Some(expected) = declared {
                        if artifact.sha256 != expected {
                            return Err(AdmissionError::at_path(
                                E_INVALID_ARTIFACT_DIGEST,
                                format!("{path}.sha256"),
                                format!(
                                    "declared digest {expected} does not match fixture {}",
                                    artifact.sha256
                                ),
                            ));
                        }
                    }
                    if let Some(Value::Number(size)) = map.get("size") {
                        if let Some(size) = size.as_u64() {
                            artifact.size = Some(size);
                        }
                    }
                    Ok(artifact)
                } else {
                    declared.map_or_else(
                        || {
                            Err(AdmissionError::at_path(
                                E_INVALID_FIELD,
                                path,
                                "artifact requires sha256 or path",
                            ))
                        },
                        |digest| {
                            Ok(Self {
                                sha256: digest,
                                size: map.get("size").and_then(Value::as_u64),
                                object: None,
                            })
                        },
                    )
                }
            }
            _ => Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                path,
                "artifact must be a digest string or object",
            )),
        }
    }
}

pub(crate) fn normalize_sha256(input: &str) -> Result<String> {
    let trimmed = input.trim();
    let digest = trimmed
        .strip_prefix("sha256:")
        .or_else(|| trimmed.strip_prefix("SHA256:"))
        .unwrap_or(trimmed);
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AdmissionError::new(
            E_INVALID_ARTIFACT_DIGEST,
            format!("expected 64 hexadecimal SHA-256 characters, got {input:?}"),
        ));
    }
    Ok(digest.to_ascii_lowercase())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
