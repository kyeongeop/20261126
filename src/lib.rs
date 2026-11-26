//! Archive structure admission for the release artifact management platform.
//!
//! Release uploads used to validate only the SHA-256 digest of the outer
//! archive.  This crate opens supported archives, builds the internal member
//! tree, and reports unsafe members (absolute paths, traversal, symlink
//! escapes, duplicates and abnormal permissions).  Fixed-package re-uploads
//! are additionally compared with the previous release archive.
//!
//! Runtime inputs are confined to a repository fixture root.  The public
//! error and issue identifiers are part of the contract and are never reused.

pub mod archive;
pub mod check;
pub mod cli;
pub mod codes;
pub mod compare;
pub mod digest;
pub mod error;
pub mod fixtures;
pub mod html;
pub mod inflate;
pub mod inspect;
pub mod manifest;
pub mod model;
pub mod path;
pub mod report;
pub mod tar;
pub mod zip;

pub use archive::{Archive, ArchiveFormat, Member, MemberKind};
pub use check::{check_archive, CheckOptions};
pub use codes::{IssueCode, Severity};
pub use compare::compare_structure;
pub use error::{AppError, AppResult, ErrorCode};
pub use fixtures::FixtureStore;
pub use html::render_html;
pub use manifest::UploadManifest;
pub use model::{StructureReport, Verdict};
pub use report::build_report;

/// Feature identifier written into every JSON report.
pub const FEATURE_ID: &str = "archive-structure-check";

/// Human-readable feature name used by the platform UI.
pub const FEATURE_NAME_ZH: &str = "压缩包结构检查";

/// JSON schema version for reports.  Increment only for incompatible changes.
pub const REPORT_SCHEMA_VERSION: &str = "1";
