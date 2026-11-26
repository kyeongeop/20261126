use crate::config::{parse_policies_json, parse_policies_value, AdmissionPolicy};
use crate::error::{AdmissionError, Result, E_INVALID_FIELD};
use crate::model::{
    AdmissionDecision, AdmissionReport, AdmissionRequest, PolicyHit, Signature, SignatureFinding,
};
use serde_json::Value;
use std::collections::HashSet;

use crate::error::{
    E_ALGORITHM_NOT_ALLOWED, E_DIGEST_MISMATCH, E_DUPLICATE_SIGNER, E_INSUFFICIENT_SIGNATURES,
    E_POLICY_OUTSIDE_VALIDITY, E_POLICY_REVOKED, E_PUBLISHER_OUT_OF_SCOPE,
    E_REQUIRED_PUBLISHER_MISSING, E_SIGNATURE_OUTSIDE_VALIDITY, E_SIGNATURE_REVOKED,
};

/// Unified entry point for pre-publication signature admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionEngine {
    policies: Vec<AdmissionPolicy>,
}

impl AdmissionEngine {
    pub fn new(policies: Vec<AdmissionPolicy>) -> Result<Self> {
        let mut ids = HashSet::new();
        for policy in &policies {
            if policy.id.is_empty() {
                return Err(AdmissionError::at_path(
                    E_INVALID_FIELD,
                    "policies",
                    "policy id must not be empty",
                ));
            }
            if policy.required_signatures == 0 {
                return Err(AdmissionError::at_path(
                    E_INVALID_FIELD,
                    format!("policies.{}", policy.id),
                    "required_signatures must be at least 1",
                ));
            }
            if policy.validity.is_inverted() {
                return Err(AdmissionError::at_path(
                    E_INVALID_FIELD,
                    format!("policies.{}", policy.id),
                    "validity window is inverted",
                ));
            }
            if !ids.insert(policy.id.clone()) {
                return Err(AdmissionError::at_path(
                    E_INVALID_FIELD,
                    format!("policies.{}", policy.id),
                    "duplicate policy id",
                ));
            }
        }
        Ok(Self { policies })
    }

    pub fn from_json_str(input: &str) -> Result<Self> {
        Self::new(parse_policies_json(input)?)
    }

    pub fn from_json(input: &str) -> Result<Self> {
        Self::from_json_str(input)
    }

    pub fn from_value(value: &Value) -> Result<Self> {
        Self::new(parse_policies_value(value)?)
    }

    pub fn policies(&self) -> &[AdmissionPolicy] {
        &self.policies
    }

    /// Evaluate all product-line policies and return the full ordered chain.
    pub fn evaluate(&self, request: &AdmissionRequest) -> AdmissionReport {
        let mut applicable = self
            .policies
            .iter()
            .filter(|policy| policy.applies_to_product_line(&request.product_line))
            .collect::<Vec<_>>();
        if applicable.is_empty() {
            return AdmissionReport::no_policy();
        }

        applicable.sort_by_key(|policy| policy.priority);
        let mut policy_chain = Vec::with_capacity(applicable.len());
        let mut report_codes = Vec::new();
        let mut decision = AdmissionDecision::Allow;

        for policy in applicable {
            let hit = evaluate_policy(policy, request);
            if hit.decision == AdmissionDecision::Deny {
                decision = AdmissionDecision::Deny;
            }
            for code in &hit.error_codes {
                push_unique(&mut report_codes, code);
            }
            policy_chain.push(hit);
        }

        AdmissionReport {
            decision,
            policy_chain,
            error_codes: report_codes,
        }
    }

    /// Alias for evaluating before a release is published.
    pub fn preflight(&self, request: &AdmissionRequest) -> AdmissionReport {
        self.evaluate(request)
    }

    pub fn preview(&self, request: &AdmissionRequest) -> AdmissionReport {
        self.evaluate(request)
    }

    pub fn admit(&self, request: &AdmissionRequest) -> AdmissionReport {
        self.evaluate(request)
    }

    pub fn evaluate_json_str(&self, input: &str) -> Result<AdmissionReport> {
        Ok(self.evaluate(&AdmissionRequest::from_json_str(input)?))
    }

    pub fn evaluate_json(&self, input: &str) -> Result<AdmissionReport> {
        self.evaluate_json_str(input)
    }

    pub fn admit_json(&self, input: &str) -> Result<AdmissionReport> {
        self.evaluate_json_str(input)
    }
}

fn evaluate_policy(policy: &AdmissionPolicy, request: &AdmissionRequest) -> PolicyHit {
    if policy.is_revoked_at(request.publish_at) {
        return denied_hit(policy, vec![E_POLICY_REVOKED]);
    }
    if !policy.validity.contains(request.publish_at) {
        return denied_hit(policy, vec![E_POLICY_OUTSIDE_VALIDITY]);
    }

    let mut seen_keys = HashSet::<String>::new();
    let mut accepted_publishers = HashSet::<String>::new();
    let mut accepted_signatures = Vec::new();
    let mut accepted_publisher_list = Vec::new();
    let mut signature_findings = Vec::with_capacity(request.signatures.len());
    let mut rejected_signature_codes = Vec::new();
    let mut policy_failure_codes = Vec::new();

    for signature in &request.signatures {
        let mut codes = signature_failure_codes(policy, request, signature);
        let duplicate_key = !seen_keys.insert(signature.key_id.clone());
        if duplicate_key {
            push_unique(&mut codes, E_DUPLICATE_SIGNER);
        }
        if policy.require_distinct_publishers && accepted_publishers.contains(&signature.publisher)
        {
            push_unique(&mut codes, E_DUPLICATE_SIGNER);
        }

        let accepted = codes.is_empty();
        if accepted {
            accepted_signatures.push(signature.key_id.clone());
            if accepted_publishers.insert(signature.publisher.clone()) {
                accepted_publisher_list.push(signature.publisher.clone());
            }
        } else {
            for code in &codes {
                push_unique(&mut rejected_signature_codes, code);
            }
        }
        signature_findings.push(SignatureFinding {
            key_id: signature.key_id.clone(),
            publisher: signature.publisher.clone(),
            accepted,
            error_codes: codes,
        });
    }

    if accepted_signatures.len() < policy.required_signatures {
        push_unique(&mut policy_failure_codes, E_INSUFFICIENT_SIGNATURES);
    }

    for required_publisher in &policy.required_publishers {
        let present = accepted_publishers
            .iter()
            .any(|publisher| crate::config::glob_match(required_publisher, publisher));
        if !present {
            push_unique(&mut policy_failure_codes, E_REQUIRED_PUBLISHER_MISSING);
        }
    }

    let decision = if policy_failure_codes.is_empty() {
        AdmissionDecision::Allow
    } else {
        AdmissionDecision::Deny
    };
    let error_codes = if decision == AdmissionDecision::Deny {
        for code in rejected_signature_codes {
            push_unique(&mut policy_failure_codes, code);
        }
        policy_failure_codes
    } else {
        Vec::new()
    };
    PolicyHit {
        policy_id: policy.id.clone(),
        priority: policy.priority,
        decision,
        error_codes,
        accepted_signatures,
        accepted_publishers: accepted_publisher_list,
        required_signatures: policy.required_signatures,
        signature_findings,
    }
}

fn signature_failure_codes(
    policy: &AdmissionPolicy,
    request: &AdmissionRequest,
    signature: &Signature,
) -> Vec<&'static str> {
    let mut codes = Vec::new();
    if signature.is_revoked_at(request.publish_at) {
        codes.push(E_SIGNATURE_REVOKED);
    }
    if !signature.validity.contains(request.publish_at) {
        codes.push(E_SIGNATURE_OUTSIDE_VALIDITY);
    }
    if !policy.algorithm_allowed(&signature.algorithm) {
        codes.push(E_ALGORITHM_NOT_ALLOWED);
    }
    if !policy.publisher_scope.includes(&signature.publisher) {
        codes.push(E_PUBLISHER_OUT_OF_SCOPE);
    }
    if policy.require_artifact_binding && !request.artifact.matches(&signature.artifact_sha256) {
        codes.push(E_DIGEST_MISMATCH);
    }
    codes
}

fn denied_hit(policy: &AdmissionPolicy, codes: Vec<&'static str>) -> PolicyHit {
    PolicyHit {
        policy_id: policy.id.clone(),
        priority: policy.priority,
        decision: AdmissionDecision::Deny,
        error_codes: codes,
        accepted_signatures: Vec::new(),
        accepted_publishers: Vec::new(),
        required_signatures: policy.required_signatures,
        signature_findings: Vec::new(),
    }
}

fn push_unique(codes: &mut Vec<&'static str>, code: &'static str) {
    if !codes.contains(&code) {
        codes.push(code);
    }
}
