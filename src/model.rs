//! Domain model for the multi-target hardening gate.
//!
//! The JSON schema produced by [`Check::to_json`] and downstream report
//! types is stable: check ids are exactly `pie`, `nx`, `relro`, `bind_now`
//! and `symbol_evidence`, and statuses are `pass`, `fail`, `unknown` and
//! `not_applicable`.

use serde_json::{json, Value};

/// Tri-state verdict plus an explicit not-applicable state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Property was positively verified.
    Pass,
    /// Property was positively verified as missing/insecure.
    Fail,
    /// The artifact does not expose enough information to decide.
    Unknown,
    /// The check has no meaning for this target type.
    NotApplicable,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Unknown => "unknown",
            Status::NotApplicable => "not_applicable",
        }
    }

    /// A required check clears the gate only with an explicit `pass`.
    pub fn clears_gate(self) -> bool {
        matches!(self, Status::Pass | Status::NotApplicable)
    }
}

/// Kind of release target. The gate matrix differs per kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetType {
    Executable,
    SharedLibrary,
    StaticLibrary,
    Relocatable,
    /// Regular file that is not an object/archive (docs, scripts, …).
    Other,
}

impl TargetType {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetType::Executable => "executable",
            TargetType::SharedLibrary => "shared_library",
            TargetType::StaticLibrary => "static_library",
            TargetType::Relocatable => "relocatable",
            TargetType::Other => "other",
        }
    }

    /// Canonical file extension token used in manifests.
    pub fn token(self) -> &'static str {
        self.as_str()
    }
}

/// Where a cited symbol was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolRef {
    pub name: String,
    /// `dynsym`, `symtab`, or `archive:<member>`.
    pub origin: String,
    /// Optional classification, e.g. `stack_canary` / `fortify`.
    pub evidence_kind: Option<String>,
}

impl SymbolRef {
    pub fn new(name: impl Into<String>, origin: impl Into<String>) -> Self {
        SymbolRef {
            name: name.into(),
            origin: origin.into(),
            evidence_kind: None,
        }
    }

    pub fn with_kind(mut self, kind: impl Into<String>) -> Self {
        self.evidence_kind = Some(kind.into());
        self
    }

    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "name": self.name,
            "origin": self.origin,
        });
        if let Some(kind) = &self.evidence_kind {
            value["evidence_kind"] = json!(kind);
        }
        value
    }
}

/// A single hardening check result for one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Stable machine id: `pie`, `nx`, `relro`, `bind_now`, `symbol_evidence`.
    pub id: String,
    /// Human label, e.g. `BIND_NOW`.
    pub label: String,
    pub status: Status,
    /// Whether the target-type matrix requires this check to pass.
    pub required: bool,
    pub reason_code: String,
    pub summary: String,
    /// Non-symbol factual evidence (headers, segments, counts…).
    pub evidence: Vec<String>,
    /// Concrete symbol citations (primarily for `symbol_evidence`).
    pub symbols: Vec<SymbolRef>,
}

impl Check {
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        status: Status,
        required: bool,
        reason_code: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Check {
            id: id.into(),
            label: label.into(),
            status,
            required,
            reason_code: reason_code.into(),
            summary: summary.into(),
            evidence: Vec::new(),
            symbols: Vec::new(),
        }
    }

    pub fn evidence_line(mut self, line: impl Into<String>) -> Self {
        self.evidence.push(line.into());
        self
    }

    pub fn evidence_lines(mut self, lines: impl IntoIterator<Item = String>) -> Self {
        self.evidence.extend(lines);
        self
    }

    pub fn symbol(mut self, symbol: SymbolRef) -> Self {
        self.symbols.push(symbol);
        self
    }

    pub fn with_status(mut self, status: Status) -> Self {
        self.status = status;
        self
    }

    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.reason_code = code.into();
        self
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = summary.into();
        self
    }

    pub fn symbols(mut self, symbols: impl IntoIterator<Item = SymbolRef>) -> Self {
        self.symbols.extend(symbols);
        self
    }

    /// True when this check contributes a blocking condition for a required
    /// target. `unknown` blocks under the fail-closed release policy.
    pub fn is_blocking(&self) -> bool {
        if !self.required {
            return false;
        }
        matches!(self.status, Status::Fail | Status::Unknown)
    }

    pub fn to_json(&self) -> Value {
        let blocking = self.is_blocking();
        json!({
            "id": self.id,
            "name": self.label,
            "label": self.label,
            // Common alias for consumers that key on the upper-case token.
            "key": self.id.to_uppercase(),
            "status": self.status.as_str(),
            "verdict": self.status.as_str(),
            "required": self.required,
            "applicable": self.status != Status::NotApplicable,
            "blocking": blocking,
            "blocks_release": blocking,
            "reason_code": self.reason_code,
            "code": self.reason_code,
            "summary": self.summary,
            "evidence": self.evidence,
            "symbols": self.symbols.iter().map(SymbolRef::to_json).collect::<Vec<_>>(),
        })
    }
}
