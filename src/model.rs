use serde_json::Value;

use crate::archive::MemberKind;
use crate::codes::{IssueCode, Severity};
use crate::inspect::ObjectInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Blocked,
}

impl Verdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Blocked => "blocked",
        }
    }

    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Accepted => "允许发布",
            Self::Blocked => "阻止发布",
        }
    }
}

/// A finding attached to a concrete archive member, or to the archive /
/// re-upload relationship when no member is involved.
#[derive(Debug, Clone)]
pub struct Finding {
    pub code: IssueCode,
    pub severity: Severity,
    pub member_index: Option<usize>,
    pub member_name: Option<String>,
    pub member_path: Option<String>,
    pub message: String,
    pub details: Value,
    pub origin: FindingOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingOrigin {
    Structure,
    Archive,
    Reupload,
}

impl FindingOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Structure => "structure",
            Self::Archive => "archive",
            Self::Reupload => "reupload",
        }
    }
}

impl Finding {
    pub fn structure(
        code: IssueCode,
        member: Option<&MemberReport>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            severity: code.severity(),
            member_index: member.map(|member| member.index),
            member_name: member.map(|member| member.name.clone()),
            member_path: member.map(|member| member.path.clone()),
            message: message.into(),
            details: Value::Null,
            origin: FindingOrigin::Structure,
        }
    }

    pub fn archive(code: IssueCode, message: impl Into<String>, details: Value) -> Self {
        Self {
            code,
            severity: code.severity(),
            member_index: None,
            member_name: None,
            member_path: None,
            message: message.into(),
            details,
            origin: FindingOrigin::Archive,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }

    pub fn is_blocking(&self) -> bool {
        self.severity == Severity::Blocking
    }

    pub fn sort_key(&self) -> (u8, Option<usize>, &'static str) {
        let origin = match self.origin {
            FindingOrigin::Archive => 0,
            FindingOrigin::Structure => 1,
            FindingOrigin::Reupload => 2,
        };
        (origin, self.member_index, self.code.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct MemberReport {
    pub index: usize,
    pub name: String,
    pub path: String,
    pub kind: MemberKind,
    pub mode: Option<u32>,
    pub unix_mode: bool,
    pub size: u64,
    pub compressed_size: Option<u64>,
    pub sha256: Option<String>,
    pub link_target: Option<String>,
    pub resolved_link_target: Option<String>,
    pub object: Option<ObjectInfo>,
    pub shebang: bool,
    pub issues: Vec<Finding>,
}

impl MemberReport {
    pub fn status(&self) -> Severity {
        self.issues
            .iter()
            .map(|issue| issue.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    pub fn blocking_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|issue| issue.is_blocking())
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|issue| issue.severity == Severity::Warning)
            .count()
    }

    pub fn mode_octal(&self) -> Option<String> {
        self.mode.map(|mode| format!("{:04o}", mode & 0o7777))
    }
}

#[derive(Debug, Clone)]
pub struct ArchiveSummary {
    pub fixture_path: String,
    pub format: String,
    pub sha256: String,
    pub declared_sha256: Option<String>,
    pub size: u64,
    pub member_count: usize,
    pub total_uncompressed: u64,
}

#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub name: String,
    pub version: String,
    pub build: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChangeEntry {
    pub path: String,
    pub previous_index: Option<usize>,
    pub current_index: Option<usize>,
    pub fields: Vec<String>,
    pub detail: Value,
}

#[derive(Debug, Clone)]
pub struct ComparisonReport {
    pub previous: ArchiveSummary,
    pub current: ArchiveSummary,
    pub unchanged: usize,
    pub added: Vec<ChangeEntry>,
    pub removed: Vec<ChangeEntry>,
    pub changed: Vec<ChangeEntry>,
    pub findings: Vec<Finding>,
    pub same_structure: bool,
}

#[derive(Debug, Clone)]
pub struct StructureReport {
    pub manifest_path: String,
    pub release: ReleaseInfo,
    pub archive: ArchiveSummary,
    pub previous: Option<ArchiveSummary>,
    pub reupload: bool,
    pub members: Vec<MemberReport>,
    pub findings: Vec<Finding>,
    pub comparison: Option<ComparisonReport>,
    pub verdict: Verdict,
}

impl StructureReport {
    pub fn blocking_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|issue| issue.is_blocking())
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|issue| issue.severity == Severity::Warning)
            .count()
    }

    pub fn info_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|issue| issue.severity == Severity::Info)
            .count()
    }
}
