//! Configurable signature admission for release artifacts.
//!
//! The crate evaluates every policy that applies to an artifact's product line
//! and returns the complete policy hit chain before a release is published.
//! A single denying policy is sufficient to deny the release.

pub mod artifact;
pub mod config;
pub mod engine;
pub mod error;
mod json_support;
pub mod model;
pub mod time;

pub use artifact::{Artifact, ObjectMetadata};
pub use config::{
    AdmissionPolicy, PolicyStatus, PublisherScope, SignatureAlgorithm, ValidityWindow,
};
pub use engine::AdmissionEngine;
pub use error::{
    AdmissionError, Result, E_ALGORITHM_NOT_ALLOWED, E_ARTIFACT_IO, E_CONFIG_IO, E_DIGEST_MISMATCH,
    E_DUPLICATE_SIGNER, E_INSUFFICIENT_SIGNATURES, E_INVALID_ARTIFACT_DIGEST, E_INVALID_CONFIG,
    E_INVALID_FIELD, E_INVALID_REQUEST, E_INVALID_TIMESTAMP, E_NO_POLICY_MATCHED,
    E_POLICY_OUTSIDE_VALIDITY, E_POLICY_REVOKED, E_PUBLISHER_OUT_OF_SCOPE, E_REQUEST_IO,
    E_REQUIRED_PUBLISHER_MISSING, E_SIGNATURE_OUTSIDE_VALIDITY, E_SIGNATURE_REVOKED,
};
pub use model::{
    AdmissionDecision, AdmissionReport, AdmissionRequest, PolicyHit, Signature, SignatureFinding,
    SignatureStatus,
};

/// Parse a policy document and a request document, then return the full
/// pre-publication policy chain.
pub fn preflight(policy_json: &str, request_json: &str) -> Result<AdmissionReport> {
    AdmissionEngine::from_json_str(policy_json)?.evaluate_json_str(request_json)
}

/// Alias for [`preflight`].
pub fn evaluate(policy_json: &str, request_json: &str) -> Result<AdmissionReport> {
    preflight(policy_json, request_json)
}

/// Alias for [`preflight`], usable at the publication admission boundary.
pub fn admit(policy_json: &str, request_json: &str) -> Result<AdmissionReport> {
    preflight(policy_json, request_json)
}
