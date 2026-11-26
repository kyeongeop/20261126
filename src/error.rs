use std::fmt;

/// Invalid JSON in the policy document.
pub const E_INVALID_CONFIG: &str = "SIG1001";
/// A required field is missing or has the wrong JSON type.
pub const E_INVALID_FIELD: &str = "SIG1002";
/// A timestamp is malformed or outside the supported range.
pub const E_INVALID_TIMESTAMP: &str = "SIG1003";
/// An artifact SHA-256 digest is malformed.
pub const E_INVALID_ARTIFACT_DIGEST: &str = "SIG1004";
/// An artifact fixture could not be read.
pub const E_ARTIFACT_IO: &str = "SIG1005";
/// Invalid JSON or shape in a publication request.
pub const E_INVALID_REQUEST: &str = "SIG1006";
/// The policy configuration file could not be read.
pub const E_CONFIG_IO: &str = "SIG1007";
/// The publication request file could not be read.
pub const E_REQUEST_IO: &str = "SIG1008";

/// No policy product-line scope matched the release.
pub const E_NO_POLICY_MATCHED: &str = "SIG2001";
/// A matched policy is revoked.
pub const E_POLICY_REVOKED: &str = "SIG2002";
/// A matched policy is outside its validity window.
pub const E_POLICY_OUTSIDE_VALIDITY: &str = "SIG2003";

/// A matched policy did not receive enough accepted signatures.
pub const E_INSUFFICIENT_SIGNATURES: &str = "SIG3001";
/// A signature publisher is outside the policy's publisher scope.
pub const E_PUBLISHER_OUT_OF_SCOPE: &str = "SIG3002";
/// A signature is outside its validity window at publish time.
pub const E_SIGNATURE_OUTSIDE_VALIDITY: &str = "SIG3003";
/// A signature is revoked at publish time.
pub const E_SIGNATURE_REVOKED: &str = "SIG3004";
/// A signature is not bound to the release artifact digest.
pub const E_DIGEST_MISMATCH: &str = "SIG3005";
/// A signature algorithm is not accepted by a policy.
pub const E_ALGORITHM_NOT_ALLOWED: &str = "SIG3006";
/// A duplicate signer did not satisfy a distinct-signer policy.
pub const E_DUPLICATE_SIGNER: &str = "SIG3007";
/// A policy's explicitly required publisher is absent.
pub const E_REQUIRED_PUBLISHER_MISSING: &str = "SIG3008";

/// Stable, machine-readable admission failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionError {
    code: &'static str,
    message: String,
    path: Option<String>,
}

impl AdmissionError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            path: None,
        }
    }

    pub fn at_path(
        code: &'static str,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            path: Some(path.into()),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "decision": "error",
            "error": {
                "code": self.code,
                "message": self.message,
                "path": self.path,
            }
        })
    }
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(path) => write!(f, "{} at {}: {}", self.code, path, self.message),
            None => write!(f, "{}: {}", self.code, self.message),
        }
    }
}

impl std::error::Error for AdmissionError {}

impl From<std::io::Error> for AdmissionError {
    fn from(error: std::io::Error) -> Self {
        Self::new(E_ARTIFACT_IO, error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AdmissionError>;
