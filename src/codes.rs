//! Stable machine-readable codes and process exit codes.
//!
//! These string values are part of the release-gate contract. They must not
//! be renamed or removed once published; new codes may only be added.

/// Exit code when every required target passes the gate.
pub const EXIT_PASS: i32 = 0;
/// Exit code when at least one required target fails (or is `unknown` under
/// the default fail-closed policy).
pub const EXIT_BLOCKED: i32 = 2;
/// Exit code for operational errors (bad arguments, unreadable manifest, …).
pub const EXIT_RUNTIME_ERROR: i32 = 1;
/// Exit code for invalid command-line usage.
pub const EXIT_USAGE: i32 = 64;

/// Overall gate decision strings.
pub const DECISION_PASSED: &str = "passed";
pub const DECISION_BLOCKED: &str = "blocked";

/// Per-target rollup strings.
pub const TARGET_PASS: &str = "pass";
pub const TARGET_FAIL: &str = "fail";
pub const TARGET_UNKNOWN: &str = "unknown";
pub const TARGET_NOT_GATED: &str = "not_gated";

// ---- Artifact / I/O error codes -------------------------------------------

pub const ARTIFACT_OK: &str = "OK";
pub const E_PATH_NOT_FOUND: &str = "E_PATH_NOT_FOUND";
pub const E_PATH_READ: &str = "E_PATH_READ";
pub const E_NOT_A_FILE: &str = "E_NOT_A_FILE";
pub const E_ARTIFACT_EMPTY: &str = "E_ARTIFACT_EMPTY";
/// Bytes look like an object/archive but could not be parsed.
pub const E_ARTIFACT_PARSE: &str = "E_ARTIFACT_PARSE";
/// Path has an artifact extension but the content is of another shape.
pub const E_ARTIFACT_KIND_MISMATCH: &str = "E_ARTIFACT_KIND_MISMATCH";
pub const E_MANIFEST_READ: &str = "E_MANIFEST_READ";
pub const E_MANIFEST_PARSE: &str = "E_MANIFEST_PARSE";
pub const E_REPORT_WRITE: &str = "E_REPORT_WRITE";
pub const E_USAGE: &str = "E_USAGE";

// ---- Check reason codes ----------------------------------------------------

pub const PIE_PASS: &str = "PIE_PASS";
pub const PIE_PASS_DSO_PIC: &str = "PIE_PASS_DSO_PIC";
pub const PIE_FAIL_ET_EXEC: &str = "PIE_FAIL_ET_EXEC";
pub const PIE_FAIL_NOT_PIE: &str = "PIE_FAIL_NOT_PIE";
pub const PIE_UNKNOWN: &str = "PIE_UNKNOWN";
pub const PIE_NOT_APPLICABLE: &str = "PIE_NOT_APPLICABLE";

pub const NX_PASS_STACK_NOEXEC: &str = "NX_PASS_STACK_NOEXEC";
pub const NX_PASS_NOTE_NOEXEC: &str = "NX_PASS_NOTE_NOEXEC";
pub const NX_FAIL_STACK_EXEC: &str = "NX_FAIL_STACK_EXEC";
pub const NX_FAIL_NOTE_EXEC: &str = "NX_FAIL_NOTE_EXEC";
pub const NX_UNKNOWN_NO_STACK_SEGMENT: &str = "NX_UNKNOWN_NO_STACK_SEGMENT";
pub const NX_UNKNOWN_MEMBER: &str = "NX_UNKNOWN_MEMBER";
pub const NX_NOT_APPLICABLE: &str = "NX_NOT_APPLICABLE";

pub const RELRO_PASS: &str = "RELRO_PASS_GNU_RELRO";
pub const RELRO_FAIL_MISSING: &str = "RELRO_FAIL_NO_GNU_RELRO";
pub const RELRO_UNKNOWN_NO_DYNAMIC: &str = "RELRO_UNKNOWN_NO_DYNAMIC";
pub const RELRO_NOT_APPLICABLE: &str = "RELRO_NOT_APPLICABLE";

pub const BIND_NOW_PASS: &str = "BIND_NOW_PASS";
pub const BIND_NOW_FAIL_LAZY: &str = "BIND_NOW_FAIL_LAZY_BINDING";
pub const BIND_NOW_UNKNOWN_NO_DYNAMIC: &str = "BIND_NOW_UNKNOWN_NO_DYNAMIC";
pub const BIND_NOW_NOT_APPLICABLE: &str = "BIND_NOW_NOT_APPLICABLE";

pub const SYMBOL_PASS: &str = "SYMBOL_EVIDENCE_PASS";
pub const SYMBOL_PASS_HARDENING: &str = "SYMBOL_EVIDENCE_PASS_WITH_HARDENING_SYMBOLS";
pub const SYMBOL_FAIL_REQUIRED_MISSING: &str = "SYMBOL_EVIDENCE_FAIL_REQUIRED_MISSING";
pub const SYMBOL_UNKNOWN_NO_TABLE: &str = "SYMBOL_EVIDENCE_UNKNOWN_NO_SYMBOL_TABLE";
pub const SYMBOL_UNKNOWN_EMPTY_ARCHIVE: &str = "SYMBOL_EVIDENCE_UNKNOWN_EMPTY_ARCHIVE";
pub const SYMBOL_UNKNOWN_PARSE: &str = "SYMBOL_EVIDENCE_UNKNOWN_PARSE";
pub const SYMBOL_NOT_APPLICABLE: &str = "SYMBOL_EVIDENCE_NOT_APPLICABLE";

/// Every stable error/reason code, useful for documentation and tests.
pub const ALL_CODES: &[&str] = &[
    ARTIFACT_OK,
    E_PATH_NOT_FOUND,
    E_PATH_READ,
    E_NOT_A_FILE,
    E_ARTIFACT_EMPTY,
    E_ARTIFACT_PARSE,
    E_ARTIFACT_KIND_MISMATCH,
    E_MANIFEST_READ,
    E_MANIFEST_PARSE,
    E_REPORT_WRITE,
    E_USAGE,
    PIE_PASS,
    PIE_PASS_DSO_PIC,
    PIE_FAIL_ET_EXEC,
    PIE_FAIL_NOT_PIE,
    PIE_UNKNOWN,
    PIE_NOT_APPLICABLE,
    NX_PASS_STACK_NOEXEC,
    NX_PASS_NOTE_NOEXEC,
    NX_FAIL_STACK_EXEC,
    NX_FAIL_NOTE_EXEC,
    NX_UNKNOWN_NO_STACK_SEGMENT,
    NX_UNKNOWN_MEMBER,
    NX_NOT_APPLICABLE,
    RELRO_PASS,
    RELRO_FAIL_MISSING,
    RELRO_UNKNOWN_NO_DYNAMIC,
    RELRO_NOT_APPLICABLE,
    BIND_NOW_PASS,
    BIND_NOW_FAIL_LAZY,
    BIND_NOW_UNKNOWN_NO_DYNAMIC,
    BIND_NOW_NOT_APPLICABLE,
    SYMBOL_PASS,
    SYMBOL_PASS_HARDENING,
    SYMBOL_FAIL_REQUIRED_MISSING,
    SYMBOL_UNKNOWN_NO_TABLE,
    SYMBOL_UNKNOWN_EMPTY_ARCHIVE,
    SYMBOL_UNKNOWN_PARSE,
    SYMBOL_NOT_APPLICABLE,
];
