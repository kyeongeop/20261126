use serde_json::{json, Value};

use crate::codes::IssueCode;
use crate::digest::sha256_hex;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::inflate::{gunzip, is_gzip, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES};
use crate::tar::parse_tar;
use crate::zip::parse_zip;

/// Supported container formats.  The name is part of the JSON contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    Tar,
    TarGz,
}

impl ArchiveFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::TarGz => "tar.gz",
        }
    }
}

/// Internal member type.  `Other` keeps the original tar type byte so the
/// report can explain why an unusual file was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    File,
    Directory,
    Symlink,
    HardLink,
    CharacterDevice,
    BlockDevice,
    Fifo,
    Other,
}

impl MemberKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::HardLink => "hard_link",
            Self::CharacterDevice => "character_device",
            Self::BlockDevice => "block_device",
            Self::Fifo => "fifo",
            Self::Other => "other",
        }
    }

    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::File => "文件",
            Self::Directory => "目录",
            Self::Symlink => "符号链接",
            Self::HardLink => "硬链接",
            Self::CharacterDevice => "字符设备",
            Self::BlockDevice => "块设备",
            Self::Fifo => "命名管道",
            Self::Other => "其他",
        }
    }

    pub const fn is_special(self) -> bool {
        matches!(
            self,
            Self::CharacterDevice | Self::BlockDevice | Self::Fifo | Self::Other
        )
    }

    pub const fn is_link(self) -> bool {
        matches!(self, Self::Symlink | Self::HardLink)
    }
}

/// One entry from the archive's internal file tree.
#[derive(Debug, Clone)]
pub struct Member {
    /// Zero-based position in the archive directory.
    pub index: usize,
    /// Name as stored in the archive (lossy UTF-8 when necessary).
    pub raw_name: String,
    /// Name after separator normalization, before path safety resolution.
    pub name: String,
    pub kind: MemberKind,
    pub mode: Option<u32>,
    pub unix_mode: bool,
    pub size: u64,
    pub compressed_size: Option<u64>,
    pub link_target: Option<String>,
    /// File payload.  Symlinks use `link_target` instead.
    pub data: Option<Vec<u8>>,
    pub encrypted: bool,
}

impl Member {
    pub fn display_path(&self) -> &str {
        &self.name
    }

    pub fn content(&self) -> &[u8] {
        self.data.as_deref().unwrap_or(&[])
    }

    pub fn mode_octal(&self) -> Option<String> {
        self.mode.map(|mode| format!("{:04o}", mode & 0o7777))
    }
}

/// Archive-level parse finding that is already attached to a member index.
#[derive(Debug, Clone)]
pub struct ParseFinding {
    pub code: IssueCode,
    pub member_index: Option<usize>,
    pub member_name: Option<String>,
    pub message: String,
    pub details: Value,
}

impl ParseFinding {
    pub fn new(
        code: IssueCode,
        member_index: Option<usize>,
        member_name: Option<&str>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            member_index,
            member_name: member_name.map(str::to_string),
            message: message.into(),
            details: json!({}),
        }
    }
}

/// Result of parsing one archive.  Parse findings are kept separate from
/// structural checks so that a broken encrypted member can still be listed.
#[derive(Debug, Clone)]
pub struct Archive {
    pub format: ArchiveFormat,
    pub sha256: String,
    pub size: u64,
    pub members: Vec<Member>,
    pub parse_findings: Vec<ParseFinding>,
}

impl Archive {
    pub fn total_uncompressed(&self) -> u64 {
        self.members
            .iter()
            .filter(|member| member.kind == MemberKind::File)
            .fold(0u64, |total, member| total.saturating_add(member.size))
    }
}

/// Detect and parse a ZIP, tar or gzip-compressed tar archive.
///
/// `file_name` is only used for format hints and error messages; member paths
/// are never resolved against the host filesystem.
pub fn parse_archive(file_name: &str, bytes: &[u8]) -> AppResult<Archive> {
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(AppError::at_path(
            ErrorCode::ArchiveParseFailed,
            file_name,
            "archive exceeds the configured input size limit",
        ));
    }
    let lower = file_name.to_ascii_lowercase();
    let gzip = is_gzip(bytes);
    let zip_magic = bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08");
    let zip = zip_magic || (lower.ends_with(".zip") && !gzip);
    let tar_hint = lower.ends_with(".tar") || lower.ends_with(".tar.gz") || lower.ends_with(".tgz");

    let (format, members, parse_findings) = if zip {
        let (members, findings) = parse_zip(bytes).map_err(|message| {
            AppError::at_path(
                ErrorCode::ArchiveParseFailed,
                file_name,
                format!("cannot parse ZIP archive: {message}"),
            )
        })?;
        (ArchiveFormat::Zip, members, findings)
    } else if gzip {
        let expanded = gunzip(bytes, MAX_OUTPUT_BYTES).map_err(|message| {
            AppError::at_path(
                ErrorCode::ArchiveParseFailed,
                file_name,
                format!("cannot decompress gzip archive: {message}"),
            )
        })?;
        let (members, findings) = parse_tar(&expanded).map_err(|message| {
            AppError::at_path(
                ErrorCode::ArchiveParseFailed,
                file_name,
                format!("cannot parse gzip-compressed tar archive: {message}"),
            )
        })?;
        (ArchiveFormat::TarGz, members, findings)
    } else {
        match parse_tar(bytes) {
            Ok((members, findings)) => (ArchiveFormat::Tar, members, findings),
            Err(message) if tar_hint => {
                return Err(AppError::at_path(
                    ErrorCode::ArchiveParseFailed,
                    file_name,
                    format!("cannot parse tar archive: {message}"),
                ))
            }
            Err(_) => {
                return Err(AppError::at_path(
                    ErrorCode::UnsupportedArchiveFormat,
                    file_name,
                    "supported formats are ZIP, tar, tar.gz and tgz",
                ))
            }
        }
    };
    Ok(Archive {
        format,
        sha256: sha256_hex(bytes),
        size: bytes.len() as u64,
        members,
        parse_findings,
    })
}
