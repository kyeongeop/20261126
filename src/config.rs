use crate::error::{AdmissionError, Result, E_INVALID_CONFIG, E_INVALID_FIELD};
use crate::json_support::{
    object, optional_bool, optional_i64, optional_string, required_string, string_list,
};
use crate::time::Timestamp;
use serde_json::{Map, Value};
use std::collections::HashSet;

/// Signing algorithm identifier. The engine admits signatures but does not
/// perform cryptographic signature verification.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignatureAlgorithm(String);

impl SignatureAlgorithm {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn sha256() -> Self {
        Self::new("sha256")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Half-open time window: `not_before <= instant < not_after`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidityWindow {
    pub not_before: Option<Timestamp>,
    pub not_after: Option<Timestamp>,
}

impl ValidityWindow {
    pub fn contains(&self, instant: Timestamp) -> bool {
        self.not_before.map_or(true, |start| start <= instant)
            && self.not_after.map_or(true, |end| instant < end)
    }

    pub fn is_inverted(&self) -> bool {
        matches!((self.not_before, self.not_after), (Some(start), Some(end)) if start >= end)
    }
}

/// Publisher allow/deny patterns. An empty include list means all publishers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublisherScope {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl PublisherScope {
    pub fn includes(&self, publisher: &str) -> bool {
        let allowed = self.include.is_empty()
            || self
                .include
                .iter()
                .any(|pattern| glob_match(pattern, publisher));
        allowed
            && !self
                .exclude
                .iter()
                .any(|pattern| glob_match(pattern, publisher))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyStatus {
    Active,
    Revoked,
}

/// A single signature admission policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionPolicy {
    pub id: String,
    pub description: Option<String>,
    pub priority: i64,
    pub product_line_patterns: Vec<String>,
    pub publisher_scope: PublisherScope,
    pub required_signatures: usize,
    pub required_publishers: Vec<String>,
    pub require_distinct_publishers: bool,
    pub require_artifact_binding: bool,
    pub allowed_algorithms: Vec<SignatureAlgorithm>,
    pub validity: ValidityWindow,
    pub status: PolicyStatus,
    pub revoked_at: Option<Timestamp>,
}

impl AdmissionPolicy {
    pub fn applies_to_product_line(&self, product_line: &str) -> bool {
        self.product_line_patterns
            .iter()
            .any(|pattern| glob_match(pattern, product_line))
    }

    pub fn is_revoked_at(&self, instant: Timestamp) -> bool {
        self.status == PolicyStatus::Revoked
            || self
                .revoked_at
                .is_some_and(|revoked_at| revoked_at <= instant)
    }

    pub fn algorithm_allowed(&self, algorithm: &SignatureAlgorithm) -> bool {
        self.allowed_algorithms.is_empty()
            || self
                .allowed_algorithms
                .iter()
                .any(|allowed| allowed == algorithm)
    }
}

/// Parse a policy document. The root may be an array or an object containing
/// a `policies` array.
pub fn parse_policies_json(input: &str) -> Result<Vec<AdmissionPolicy>> {
    let value: Value = serde_json::from_str(input).map_err(|error| {
        AdmissionError::new(E_INVALID_CONFIG, format!("invalid policy JSON: {error}"))
    })?;
    parse_policies_value(&value)
}

pub fn parse_policies_value(value: &Value) -> Result<Vec<AdmissionPolicy>> {
    let values = match value {
        Value::Array(values) => values.as_slice(),
        Value::Object(map) => match map.get("policies") {
            Some(Value::Array(values)) => values.as_slice(),
            Some(_) => {
                return Err(AdmissionError::at_path(
                    E_INVALID_FIELD,
                    "policies",
                    "expected an array",
                ))
            }
            None => {
                return Err(AdmissionError::at_path(
                    E_INVALID_FIELD,
                    "policies",
                    "required field is missing",
                ))
            }
        },
        _ => {
            return Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                "$",
                "expected policy array or object",
            ))
        }
    };

    let mut policies = Vec::with_capacity(values.len());
    let mut ids = HashSet::new();
    for (index, value) in values.iter().enumerate() {
        let path = format!("policies[{index}]");
        let policy = AdmissionPolicy::from_json(value, &path)?;
        if !ids.insert(policy.id.clone()) {
            return Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                format!("{path}.id"),
                format!("duplicate policy id {:?}", policy.id),
            ));
        }
        policies.push(policy);
    }
    Ok(policies)
}

impl AdmissionPolicy {
    fn from_json(value: &Value, path: &str) -> Result<Self> {
        let map = object(value, path)?;
        let id = required_string(map, &["id", "policy_id"], path)?;
        if id.trim().is_empty() {
            return Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                format!("{path}.id"),
                "policy id must not be empty",
            ));
        }

        let required_signatures = optional_i64(
            map,
            &[
                "required_signatures",
                "min_signatures",
                "minimum_signatures",
            ],
            path,
        )?
        .unwrap_or(1);
        if required_signatures < 1 {
            return Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                format!("{path}.required_signatures"),
                "must be at least 1",
            ));
        }

        let validity = parse_validity(map, path)?;
        if validity.is_inverted() {
            return Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                format!("{path}.validity"),
                "valid_from must be earlier than valid_until",
            ));
        }

        let publisher_scope = parse_publisher_scope(map, path)?;
        let mut product_line_patterns =
            string_list(map, &["product_lines", "product_line", "products"], path)?;
        if product_line_patterns.is_empty() {
            product_line_patterns.push("*".to_string());
        }
        if product_line_patterns
            .iter()
            .any(|pattern| pattern.is_empty())
        {
            return Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                format!("{path}.product_lines"),
                "product line patterns must not be empty",
            ));
        }

        let mut required_publishers =
            string_list(map, &["required_publishers", "publishers_required"], path)?;
        required_publishers.retain(|publisher| !publisher.is_empty());

        let allowed_algorithms = string_list(
            map,
            &["allowed_algorithms", "algorithms", "signature_algorithms"],
            path,
        )?
        .into_iter()
        .map(SignatureAlgorithm::new)
        .collect::<Vec<_>>();
        if allowed_algorithms
            .iter()
            .any(|algorithm| algorithm.as_str().is_empty())
        {
            return Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                format!("{path}.allowed_algorithms"),
                "algorithm names must not be empty",
            ));
        }

        let status = match optional_string(map, &["status", "revocation_status"], path)?
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("active") | Some("enabled") => PolicyStatus::Active,
            Some("revoked") | Some("disabled") => PolicyStatus::Revoked,
            Some(other) => {
                return Err(AdmissionError::at_path(
                    E_INVALID_FIELD,
                    format!("{path}.status"),
                    format!("unsupported policy status {other:?}"),
                ))
            }
        };
        let status = if optional_bool(map, &["revoked"], path)?.unwrap_or(false) {
            PolicyStatus::Revoked
        } else {
            status
        };
        let revoked_at = parse_optional_timestamp(map, &["revoked_at", "revocation_time"], path)?;

        Ok(Self {
            id,
            description: optional_string(map, &["description"], path)?,
            priority: optional_i64(map, &["priority"], path)?.unwrap_or(0),
            product_line_patterns,
            publisher_scope,
            required_signatures: required_signatures as usize,
            required_publishers,
            require_distinct_publishers: optional_bool(
                map,
                &["require_distinct_publishers", "distinct_publishers"],
                path,
            )?
            .unwrap_or(false),
            require_artifact_binding: optional_bool(
                map,
                &["require_artifact_binding", "artifact_binding"],
                path,
            )?
            .unwrap_or(true),
            allowed_algorithms,
            validity,
            status,
            revoked_at,
        })
    }
}

pub(crate) fn parse_validity(map: &Map<String, Value>, path: &str) -> Result<ValidityWindow> {
    let nested = map
        .get("validity")
        .or_else(|| map.get("validity_window"))
        .or_else(|| map.get("window"));
    let nested = nested
        .map(|value| object(value, &format!("{path}.validity")))
        .transpose()?;

    let not_before = first_timestamp(
        map,
        nested,
        &["valid_from", "not_before", "validity_start"],
        &["from", "not_before", "valid_from"],
        &format!("{path}.validity"),
    )?;
    let not_after = first_timestamp(
        map,
        nested,
        &["valid_until", "not_after", "expires_at", "validity_end"],
        &["until", "to", "not_after", "expires_at", "valid_until"],
        &format!("{path}.validity"),
    )?;
    Ok(ValidityWindow {
        not_before,
        not_after,
    })
}

fn first_timestamp(
    outer: &Map<String, Value>,
    inner: Option<&Map<String, Value>>,
    outer_names: &[&str],
    inner_names: &[&str],
    path: &str,
) -> Result<Option<Timestamp>> {
    if let Some((name, value)) = outer_names
        .iter()
        .find_map(|name| outer.get_key_value(*name))
    {
        return Timestamp::parse_json(value, &format!("{path}.{name}")).map(Some);
    }
    if let Some(inner) = inner {
        if let Some((name, value)) = inner_names
            .iter()
            .find_map(|name| inner.get_key_value(*name))
        {
            return Timestamp::parse_json(value, &format!("{path}.{name}")).map(Some);
        }
    }
    Ok(None)
}

pub(crate) fn parse_optional_timestamp(
    map: &Map<String, Value>,
    names: &[&str],
    path: &str,
) -> Result<Option<Timestamp>> {
    match names.iter().find_map(|name| map.get_key_value(*name)) {
        Some((_, Value::Null)) | None => Ok(None),
        Some((name, value)) => Timestamp::parse_json(value, &format!("{path}.{name}")).map(Some),
    }
}

fn parse_publisher_scope(map: &Map<String, Value>, path: &str) -> Result<PublisherScope> {
    let mut scope = PublisherScope::default();
    match map.get("publisher_scope") {
        Some(Value::String(pattern)) => scope.include.push(pattern.clone()),
        Some(Value::Array(_)) => {
            scope.include = string_list(map, &["publisher_scope"], path)?;
        }
        Some(Value::Object(inner)) => {
            scope.include = string_list(
                inner,
                &["include", "publishers", "allow", "allowed"],
                &format!("{path}.publisher_scope"),
            )?;
            scope.exclude = string_list(
                inner,
                &["exclude", "deny", "denied"],
                &format!("{path}.publisher_scope"),
            )?;
        }
        Some(Value::Null) | None => {}
        Some(_) => {
            return Err(AdmissionError::at_path(
                E_INVALID_FIELD,
                format!("{path}.publisher_scope"),
                "expected string, array, or scope object",
            ))
        }
    }

    let top_level_publishers = string_list(
        map,
        &["publishers", "publisher_patterns", "allowed_publishers"],
        path,
    )?;
    if !top_level_publishers.is_empty() {
        if scope.include.is_empty() {
            scope.include = top_level_publishers;
        } else {
            scope.include.extend(top_level_publishers);
        }
    }
    let top_level_excluded = string_list(
        map,
        &[
            "excluded_publishers",
            "denied_publishers",
            "publisher_denylist",
        ],
        path,
    )?;
    scope.exclude.extend(top_level_excluded);
    Ok(scope)
}

/// Match identifiers with `*` (any sequence) and `?` (one character).
pub(crate) fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pattern_index, mut value_index) = (0, 0);
    let mut star_index = None;
    let mut star_value_index = 0;

    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}
