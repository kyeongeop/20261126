//! Inspect one path: read bytes, hash, classify and gather raw facts.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::archive::{inspect_archive, ArchiveInspection};
use crate::classify::{classify_archive, classify_elf, content_kind, ContentKind};
use crate::codes;
use crate::elf::{parse_structure, ElfStructure};
use crate::model::TargetType;
use crate::symbols::{collect, SymbolFacts};

#[derive(Debug, Clone)]
pub struct InspectedArtifact {
    pub path: String,
    pub display_path: String,
    pub file_name: String,
    pub target_type: TargetType,
    pub required: bool,
    pub size_bytes: u64,
    pub sha256: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub basis: Vec<String>,
    pub structure: Option<ElfStructure>,
    pub symbols: Option<SymbolFacts>,
    pub archive: Option<ArchiveInspection>,
    pub required_symbols: Vec<String>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn display_path_for(path: &Path, base: Option<&Path>) -> String {
    if let Some(base) = base {
        if let Ok(relative) = path.strip_prefix(base) {
            let rendered = relative.to_string_lossy().replace('\\', "/");
            if !rendered.is_empty() {
                return rendered;
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(relative) = path.strip_prefix(&cwd) {
            return relative.to_string_lossy().replace('\\', "/");
        }
    }
    path.to_string_lossy().replace('\\', "/")
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string_lossy().to_string())
}

/// Inspect a single path. File-level failures are recorded on the returned
/// value using a stable error code rather than propagated, so one bad artifact
/// cannot hide the rest of the release.
pub fn inspect_path(
    path: &Path,
    base: Option<&Path>,
    required: bool,
    required_symbols: Vec<String>,
) -> InspectedArtifact {
    let path_string = path.to_string_lossy().to_string();
    let display_path = display_path_for(path, base);
    let file_name = file_name_of(path);

    let mut artifact = InspectedArtifact {
        path: path_string.clone(),
        display_path,
        file_name,
        target_type: TargetType::Other,
        required,
        size_bytes: 0,
        sha256: None,
        error_code: None,
        error_message: None,
        basis: Vec::new(),
        structure: None,
        symbols: None,
        archive: None,
        required_symbols,
    };

    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            artifact.error_code = Some(codes::E_PATH_NOT_FOUND.to_string());
            artifact.error_message = Some(format!("{path_string}: {err}"));
            return artifact;
        }
    };
    if !metadata.is_file() {
        artifact.error_code = Some(codes::E_NOT_A_FILE.to_string());
        artifact.error_message = Some(format!("{} is not a regular file", path.display()));
        return artifact;
    }
    artifact.size_bytes = metadata.len();

    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            artifact.error_code = Some(codes::E_PATH_READ.to_string());
            artifact.error_message = Some(format!("{}: {err}", path.display()));
            return artifact;
        }
    };
    artifact.size_bytes = bytes.len() as u64;
    artifact.sha256 = Some(sha256_hex(&bytes));

    if bytes.is_empty() {
        artifact.error_code = Some(codes::E_ARTIFACT_EMPTY.to_string());
        artifact.error_message = Some("artifact is empty".to_string());
        artifact.basis.push("zero-byte file".to_string());
        return artifact;
    }

    match content_kind(&bytes) {
        ContentKind::Elf => inspect_elf(&mut artifact, &bytes),
        ContentKind::Archive => inspect_archive_file(&mut artifact, &bytes),
        ContentKind::Other => {
            artifact
                .basis
                .push("no ELF or ar archive magic".to_string());
            match crate::classify::classify_by_name(&artifact.display_path) {
                Some(kind) => {
                    // Name promises an artifact but the bytes do not parse:
                    // keep the target type so every check degrades to
                    // `unknown` instead of silently dropping the file.
                    artifact.target_type = kind;
                    artifact.error_code = Some(codes::E_ARTIFACT_KIND_MISMATCH.to_string());
                    artifact.error_message = Some(
                        "file name indicates a binary target but content is not ELF/ar".to_string(),
                    );
                }
                None => artifact.target_type = TargetType::Other,
            }
        }
    }

    artifact
}

fn inspect_elf(artifact: &mut InspectedArtifact, bytes: &[u8]) {
    artifact.basis.push("ELF magic 7f 45 4c 46".to_string());

    match parse_structure(bytes) {
        Ok(structure) => {
            artifact.target_type = classify_elf(
                Some(structure.e_type),
                structure.has_interp(),
                structure.has_soname(),
                &artifact.display_path,
            );
            artifact.basis.push(format!(
                "EI_CLASS={} e_type={} machine={}",
                structure.class, structure.e_type, structure.machine
            ));
            if structure.has_interp() {
                artifact.basis.push("PT_INTERP present".to_string());
            }
            artifact.structure = Some(structure);
        }
        Err(message) => {
            // Fall back to name classification but flag the parse failure.
            artifact.target_type = classify_elf(
                crate::classify::elf_e_type(bytes),
                false,
                false,
                &artifact.display_path,
            );
            artifact.error_code = Some(codes::E_ARTIFACT_PARSE.to_string());
            artifact.error_message = Some(message);
        }
    }

    let facts = collect(bytes, None);
    if let Some(err) = &facts.parse_error {
        if artifact.error_code.is_none() {
            artifact.error_code = Some(codes::E_ARTIFACT_PARSE.to_string());
            artifact.error_message = Some(err.clone());
        }
    }
    artifact.symbols = Some(facts);
}

fn inspect_archive_file(artifact: &mut InspectedArtifact, bytes: &[u8]) {
    artifact.basis.push("ar archive magic !<arch>".to_string());
    artifact.target_type = classify_archive(&artifact.display_path);
    let inspection = inspect_archive(bytes);
    if !inspection.parsed {
        artifact.error_code = Some(codes::E_ARTIFACT_PARSE.to_string());
        artifact.error_message = inspection
            .parse_error
            .clone()
            .or_else(|| Some("failed to parse ar archive".to_string()));
    }
    artifact.archive = Some(inspection);
}

/// Convenience for callers that already own bytes (tests, embedded flows).
pub fn inspect_bytes(
    display_path: impl Into<String>,
    bytes: &[u8],
    required: bool,
    required_symbols: Vec<String>,
) -> InspectedArtifact {
    let display_path = display_path.into();
    let path = PathBuf::from(&display_path);
    let file_name = file_name_of(&path);
    let mut artifact = InspectedArtifact {
        path: display_path.clone(),
        display_path,
        file_name,
        target_type: TargetType::Other,
        required,
        size_bytes: bytes.len() as u64,
        sha256: Some(sha256_hex(bytes)),
        error_code: None,
        error_message: None,
        basis: Vec::new(),
        structure: None,
        symbols: None,
        archive: None,
        required_symbols,
    };
    if bytes.is_empty() {
        artifact.error_code = Some(codes::E_ARTIFACT_EMPTY.to_string());
        return artifact;
    }
    match content_kind(bytes) {
        ContentKind::Elf => inspect_elf(&mut artifact, bytes),
        ContentKind::Archive => inspect_archive_file(&mut artifact, bytes),
        ContentKind::Other => {
            artifact.target_type = crate::classify::classify_by_name(&artifact.display_path)
                .unwrap_or(TargetType::Other);
            if artifact.target_type != TargetType::Other {
                artifact.error_code = Some(codes::E_ARTIFACT_KIND_MISMATCH.to_string());
            }
        }
    }
    artifact
}
