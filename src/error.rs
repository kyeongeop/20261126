use std::fmt;

use serde_json::{json, Value};

/// Stable runtime error codes.
///
/// These values are an external contract.  Never renumber or reuse an existing
/// code; append new variants and codes at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidArgument,
    FixtureRootNotFound,
    ManifestNotFound,
    ManifestReadFailed,
    ManifestJsonInvalid,
    ManifestSchemaInvalid,
    PathOutsideFixtureRoot,
    ArchiveNotFound,
    ArchiveReadFailed,
    UnsupportedArchiveFormat,
    ArchiveParseFailed,
    ArchiveHashMismatch,
    PreviousArchiveRequired,
    OutputWriteFailed,
    Internal,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ARC1001",
            Self::FixtureRootNotFound => "ARC1002",
            Self::ManifestNotFound => "ARC1003",
            Self::ManifestReadFailed => "ARC1004",
            Self::ManifestJsonInvalid => "ARC1005",
            Self::ManifestSchemaInvalid => "ARC1006",
            Self::PathOutsideFixtureRoot => "ARC1007",
            Self::ArchiveNotFound => "ARC1008",
            Self::ArchiveReadFailed => "ARC1009",
            Self::UnsupportedArchiveFormat => "ARC1010",
            Self::ArchiveParseFailed => "ARC1011",
            Self::ArchiveHashMismatch => "ARC1012",
            Self::PreviousArchiveRequired => "ARC1013",
            Self::OutputWriteFailed => "ARC1014",
            Self::Internal => "ARC1015",
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::FixtureRootNotFound => "FIXTURE_ROOT_NOT_FOUND",
            Self::ManifestNotFound => "MANIFEST_NOT_FOUND",
            Self::ManifestReadFailed => "MANIFEST_READ_FAILED",
            Self::ManifestJsonInvalid => "MANIFEST_JSON_INVALID",
            Self::ManifestSchemaInvalid => "MANIFEST_SCHEMA_INVALID",
            Self::PathOutsideFixtureRoot => "PATH_OUTSIDE_FIXTURE_ROOT",
            Self::ArchiveNotFound => "ARCHIVE_NOT_FOUND",
            Self::ArchiveReadFailed => "ARCHIVE_READ_FAILED",
            Self::UnsupportedArchiveFormat => "UNSUPPORTED_ARCHIVE_FORMAT",
            Self::ArchiveParseFailed => "ARCHIVE_PARSE_FAILED",
            Self::ArchiveHashMismatch => "ARCHIVE_HASH_MISMATCH",
            Self::PreviousArchiveRequired => "PREVIOUS_ARCHIVE_REQUIRED",
            Self::OutputWriteFailed => "OUTPUT_WRITE_FAILED",
            Self::Internal => "INTERNAL",
        }
    }

    /// Process exit code.  2 means "the archive was understood but blocked";
    /// runtime errors use 1 and command-line usage errors use 64.
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::InvalidArgument => 64,
            _ => 1,
        }
    }
}

/// Structured error returned by the library and CLI.
#[derive(Debug, Clone)]
pub struct AppError {
    pub code: ErrorCode,
    pub message: String,
    pub details: Value,
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: json!({}),
        }
    }

    pub fn at_path(code: ErrorCode, path: impl Into<String>, message: impl Into<String>) -> Self {
        let mut error = Self::new(code, message);
        error.details = json!({ "path": path.into() });
        error
    }

    pub fn detail(mut self, key: &str, value: impl Into<Value>) -> Self {
        if !self.details.is_object() {
            self.details = json!({});
        }
        if let Some(object) = self.details.as_object_mut() {
            object.insert(key.to_string(), value.into());
        }
        self
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": false,
            "error": {
                "code": self.code.as_str(),
                "name": self.code.name(),
                "message": self.message,
                "details": self.details,
            }
        })
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {}: {}",
            self.code.as_str(),
            self.code.name(),
            self.message
        )
    }
}

impl std::error::Error for AppError {}

pub type AppResult<T> = Result<T, AppError>;

pub fn invalid_argument(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::InvalidArgument, message)
}

pub fn internal(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, message)
}

/// Stable runtime error catalog embedded in reports.
pub fn error_catalog() -> Value {
    let codes = [
        ErrorCode::InvalidArgument,
        ErrorCode::FixtureRootNotFound,
        ErrorCode::ManifestNotFound,
        ErrorCode::ManifestReadFailed,
        ErrorCode::ManifestJsonInvalid,
        ErrorCode::ManifestSchemaInvalid,
        ErrorCode::PathOutsideFixtureRoot,
        ErrorCode::ArchiveNotFound,
        ErrorCode::ArchiveReadFailed,
        ErrorCode::UnsupportedArchiveFormat,
        ErrorCode::ArchiveParseFailed,
        ErrorCode::ArchiveHashMismatch,
        ErrorCode::PreviousArchiveRequired,
        ErrorCode::OutputWriteFailed,
        ErrorCode::Internal,
    ];
    Value::Array(
        codes
            .iter()
            .map(|code| {
                json!({
                    "code": code.as_str(),
                    "name": code.name(),
                    "exit_code": code.exit_code(),
                })
            })
            .collect(),
    )
}
