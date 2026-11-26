use crate::artifact::{normalize_sha256, Artifact};
use crate::config::{
    parse_optional_timestamp, parse_policies_value, parse_validity, AdmissionPolicy,
    SignatureAlgorithm, ValidityWindow,
};
use crate::error::{
    AdmissionError, Result, E_INVALID_FIELD, E_INVALID_REQUEST, E_NO_POLICY_MATCHED,
};
use crate::json_support::{object, optional_bool, optional_string, required_string};
use crate::time::Timestamp;
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureStatus {
    Active,
    Revoked,
}

/// Signature metadata presented to the admission engine.
///
/// Cryptographic verification happens before admission. This model checks the
/// digest binding, publisher scope, validity and revocation state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub key_id: String,
    pub publisher: String,
    pub algorithm: SignatureAlgorithm,
    pub artifact_sha256: String,
    pub validity: ValidityWindow,
    pub status: SignatureStatus,
    pub revoked_at: Option<Timestamp>,
    pub opaque_value: Option<String>,
}

impl Signature {
    pub fn is_revoked_at(&self, instant: Timestamp) -> bool {
        self.status == SignatureStatus::Revoked
            || self
                .revoked_at
                .is_some_and(|revoked_at| revoked_at <= instant)
    }

    pub fn from_json(value: &Value, path: &str) -> Result<Self> {
        let map = object(value, path)?;
        let key_id = required_string(map, &["key_id", "key", "signing_key_id"], path)?;
        if key_id.is_empty() {
            return Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                format!("{path}.key_id"),
                "signing key id must not be empty",
            ));
        }
        let publisher = required_string(map, &["publisher", "publisher_id"], path)?;
        if publisher.is_empty() {
            return Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                format!("{path}.publisher"),
                "publisher must not be empty",
            ));
        }

        let algorithm = optional_string(map, &["algorithm", "signature_algorithm"], path)?
            .unwrap_or_else(|| "sha256".to_string());
        if algorithm.is_empty() {
            return Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                format!("{path}.algorithm"),
                "algorithm must not be empty",
            ));
        }
        let algorithm = SignatureAlgorithm::new(algorithm);

        let digest = required_string(
            map,
            &[
                "artifact_sha256",
                "artifact_digest",
                "digest",
                "signed_digest",
            ],
            path,
        )?;
        let artifact_sha256 = normalize_sha256(&digest)?;

        let validity = parse_validity(map, path)?;
        if validity.is_inverted() {
            return Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                format!("{path}.validity"),
                "valid_from must be earlier than valid_until",
            ));
        }

        let status_text = optional_string(map, &["status", "revocation_status"], path)?
            .map(|status| status.to_ascii_lowercase());
        let mut status = match status_text.as_deref() {
            None | Some("active") | Some("valid") | Some("ok") => SignatureStatus::Active,
            Some("revoked") | Some("invalid") => SignatureStatus::Revoked,
            Some(other) => {
                return Err(AdmissionError::at_path(
                    E_INVALID_FIELD,
                    format!("{path}.status"),
                    format!("unsupported signature status {other:?}"),
                ))
            }
        };
        if optional_bool(map, &["revoked"], path)?.unwrap_or(false) {
            status = SignatureStatus::Revoked;
        }
        let revoked_at = parse_optional_timestamp(map, &["revoked_at", "revocation_time"], path)?;

        Ok(Self {
            key_id,
            publisher,
            algorithm,
            artifact_sha256,
            validity,
            status,
            revoked_at,
            opaque_value: optional_string(map, &["signature", "value"], path)?,
        })
    }
}

/// Input to one pre-publication admission evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionRequest {
    pub product_line: String,
    pub artifact: Artifact,
    pub signatures: Vec<Signature>,
    pub publish_at: Timestamp,
}

impl AdmissionRequest {
    pub fn from_json_str(input: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(input).map_err(|error| {
            AdmissionError::new(E_INVALID_REQUEST, format!("invalid request JSON: {error}"))
        })?;
        Self::from_value(&value)
    }

    pub fn from_value(value: &Value) -> Result<Self> {
        let map = object(value, "$")?;
        let product_line = required_string(map, &["product_line", "product", "line"], "$")?;
        if product_line.is_empty() {
            return Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                "$.product_line",
                "product line must not be empty",
            ));
        }

        let publish_at = match map
            .get("publish_at")
            .or_else(|| map.get("published_at"))
            .or_else(|| map.get("at"))
        {
            Some(value) => Timestamp::parse_json(value, "$.publish_at")?,
            None => {
                return Err(AdmissionError::at_path(
                    E_INVALID_FIELD,
                    "$.publish_at",
                    "required field is missing",
                ))
            }
        };

        let artifact = match map.get("artifact") {
            Some(value) => Artifact::from_json(value, "$.artifact")?,
            None => {
                let digest = required_string(map, &["artifact_sha256", "artifact_digest"], "$")?;
                Artifact::from_sha256(&digest)?
            }
        };

        let signatures = match map.get("signatures") {
            Some(Value::Array(values)) => values
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    Signature::from_json(value, &format!("$.signatures[{index}]"))
                })
                .collect::<Result<Vec<_>>>()?,
            Some(_) => {
                return Err(AdmissionError::at_path(
                    E_INVALID_FIELD,
                    "$.signatures",
                    "expected an array",
                ))
            }
            None => Vec::new(),
        };

        Ok(Self {
            product_line,
            artifact,
            signatures,
            publish_at,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdmissionDecision {
    Allow,
    Deny,
}

impl AdmissionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Per-signature evidence within a policy hit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureFinding {
    pub key_id: String,
    pub publisher: String,
    pub accepted: bool,
    pub error_codes: Vec<&'static str>,
}

impl SignatureFinding {
    pub fn to_json(&self) -> Value {
        json!({
            "key_id": self.key_id,
            "publisher": self.publisher,
            "accepted": self.accepted,
            "error_codes": self.error_codes,
        })
    }
}

/// One applicable policy in the ordered pre-publication policy chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyHit {
    pub policy_id: String,
    pub priority: i64,
    pub decision: AdmissionDecision,
    pub error_codes: Vec<&'static str>,
    pub accepted_signatures: Vec<String>,
    pub accepted_publishers: Vec<String>,
    pub required_signatures: usize,
    pub signature_findings: Vec<SignatureFinding>,
}

impl PolicyHit {
    pub fn to_json(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "priority": self.priority,
            "decision": self.decision.as_str(),
            "error_codes": self.error_codes,
            "accepted_signatures": self.accepted_signatures,
            "accepted_publishers": self.accepted_publishers,
            "required_signatures": self.required_signatures,
            "signature_findings": self
                .signature_findings
                .iter()
                .map(SignatureFinding::to_json)
                .collect::<Vec<_>>(),
        })
    }
}

/// Result of a pre-publication admission evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionReport {
    pub decision: AdmissionDecision,
    pub policy_chain: Vec<PolicyHit>,
    pub error_codes: Vec<&'static str>,
}

impl AdmissionReport {
    pub fn is_allowed(&self) -> bool {
        self.decision == AdmissionDecision::Allow
    }

    pub(crate) fn no_policy() -> Self {
        Self {
            decision: AdmissionDecision::Deny,
            policy_chain: Vec::new(),
            error_codes: vec![E_NO_POLICY_MATCHED],
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "decision": self.decision.as_str(),
            "error_codes": self.error_codes,
            "policy_chain": self
                .policy_chain
                .iter()
                .map(PolicyHit::to_json)
                .collect::<Vec<_>>(),
        })
    }

    pub fn to_json_string(&self) -> String {
        self.to_json().to_string()
    }

    pub fn to_json_string_pretty(&self) -> String {
        serde_json::to_string_pretty(&self.to_json())
            .expect("JSON values produced by AdmissionReport are always serializable")
    }
}

/// Parse policies from a JSON value for callers that already decoded a document.
pub fn policies_from_value(value: &Value) -> Result<Vec<AdmissionPolicy>> {
    parse_policies_value(value)
}
