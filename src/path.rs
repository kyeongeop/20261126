//! Lexical path analysis shared by archive checks and fixture loading.
//!
//! Archive paths are never resolved against the host filesystem.  We classify
//! them lexically so an unsafe member can be reported without ever extracting
//! it.  The same discipline is used for files read from the fixture root.

use std::path::{Component, Path, PathBuf};

use crate::error::{AppError, AppResult, ErrorCode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSafety {
    /// Best-effort relative path used for duplicate detection and reporting.
    pub normalized: String,
    pub absolute: bool,
    pub traversal: bool,
    /// True when `..` walks above the archive root.
    pub escape: bool,
    pub empty: bool,
    pub ambiguous_separator: bool,
    pub nul: bool,
}

impl PathSafety {
    pub fn is_suspicious(&self) -> bool {
        self.absolute || self.traversal || self.empty || self.ambiguous_separator || self.nul
    }
}

pub fn has_windows_separator(text: &str) -> bool {
    text.contains('\\')
}

pub fn is_absolute_like(text: &str) -> bool {
    let normalized = text.replace('\\', "/");
    if normalized.starts_with('/') {
        return true;
    }
    let bytes = normalized.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

pub fn contains_nul(text: &str) -> bool {
    text.as_bytes().contains(&0)
}

/// Scan an archive member name without touching the filesystem.
pub fn analyze_member_path(raw: &str) -> PathSafety {
    let nil = contains_nul(raw);
    let ambiguous_separator = has_windows_separator(raw);
    let normalized_separators = raw.replace('\\', "/");
    let absolute = is_absolute_like(raw);
    let mut segments = Vec::new();
    let mut depth = 0usize;
    let mut traversal = false;
    let mut escape = false;
    for segment in normalized_separators.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                traversal = true;
                if depth == 0 {
                    escape = true;
                    segments.push("..".to_string());
                } else {
                    depth -= 1;
                    segments.pop();
                }
            }
            value => {
                depth += 1;
                segments.push(value.to_string());
            }
        }
    }
    let normalized = segments.join("/");
    PathSafety {
        empty: normalized.is_empty(),
        normalized,
        absolute,
        traversal,
        escape,
        ambiguous_separator,
        nul: nil,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkTargetSafety {
    /// Resolved archive-relative target (best effort).
    pub resolved: String,
    pub absolute: bool,
    pub traversal: bool,
    pub escape: bool,
    pub empty: bool,
    pub ambiguous_separator: bool,
    pub nul: bool,
}

/// Resolve a symlink/hardlink target relative to its member location.
pub fn analyze_link_target(link_path: &str, target: &str) -> LinkTargetSafety {
    let nil = contains_nul(target);
    let ambiguous_separator = has_windows_separator(target);
    let absolute = is_absolute_like(target);
    let mut segments: Vec<String> = Vec::new();
    if !absolute {
        for segment in link_path.replace('\\', "/").split('/') {
            match segment {
                "" | "." => {}
                ".." => {
                    segments.pop();
                }
                value => segments.push(value.to_string()),
            }
        }
        if !segments.is_empty() {
            segments.pop();
        }
    }
    let mut depth = segments.len();
    let mut traversal = false;
    let mut escape = false;
    for segment in target.replace('\\', "/").split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                traversal = true;
                if depth == 0 {
                    escape = true;
                    segments.push("..".to_string());
                } else {
                    depth -= 1;
                    segments.pop();
                }
            }
            value => {
                depth += 1;
                segments.push(value.to_string());
            }
        }
    }
    let resolved = segments.join("/");
    LinkTargetSafety {
        empty: resolved.is_empty(),
        resolved,
        absolute,
        traversal,
        escape,
        ambiguous_separator,
        nul: nil,
    }
}

/// Hard-link names in tar are archive-root relative, unlike symlink targets
/// which are relative to the link's parent directory.
pub fn analyze_hardlink_target(target: &str) -> LinkTargetSafety {
    let safety = analyze_member_path(target);
    LinkTargetSafety {
        resolved: safety.normalized,
        absolute: safety.absolute,
        traversal: safety.traversal,
        escape: safety.escape,
        empty: safety.empty,
        ambiguous_separator: safety.ambiguous_separator,
        nul: safety.nul,
    }
}

pub fn is_path_prefix(prefix: &str, path: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }
    path.len() > prefix.len()
        && path.starts_with(prefix)
        && path.as_bytes().get(prefix.len()) == Some(&b'/')
}

/// Join a fixture-relative path to `root` and prove lexically that it cannot
/// escape.  Canonicalization happens later when the file is opened.
pub fn safe_join(root: &Path, relative: &str) -> AppResult<PathBuf> {
    if relative.trim().is_empty() {
        return Err(AppError::new(
            ErrorCode::InvalidArgument,
            "fixture path must not be empty",
        ));
    }
    if contains_nul(relative) || is_absolute_like(relative) {
        return Err(AppError::at_path(
            ErrorCode::PathOutsideFixtureRoot,
            relative,
            "fixture path must be a relative path without NUL bytes",
        ));
    }
    let candidate = Path::new(relative);
    for component in candidate.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(AppError::at_path(
                    ErrorCode::PathOutsideFixtureRoot,
                    relative,
                    "fixture path contains a traversal or root component",
                ))
            }
        }
    }
    Ok(root.join(candidate))
}

/// Canonicalize a fixture file and ensure it is still below the canonical
/// fixture root.  This protects both lexical (`..`) and symlink escapes.
pub fn confined_file(root: &Path, relative: &str) -> AppResult<PathBuf> {
    let joined = if Path::new(relative).is_absolute() {
        PathBuf::from(relative)
    } else {
        safe_join(root, relative)?
    };
    let canonical = joined.canonicalize().map_err(|error| {
        AppError::at_path(
            ErrorCode::ArchiveNotFound,
            relative,
            format!("cannot open fixture file: {error}"),
        )
    })?;
    let canonical_root = root.canonicalize().map_err(|error| {
        AppError::new(
            ErrorCode::FixtureRootNotFound,
            format!("cannot resolve fixture root {}: {error}", root.display()),
        )
    })?;
    if !canonical.starts_with(&canonical_root) {
        return Err(AppError::at_path(
            ErrorCode::PathOutsideFixtureRoot,
            relative,
            "fixture file resolves outside the fixture root",
        ));
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_absolute_and_traversal_paths() {
        assert!(analyze_member_path("/etc/passwd").absolute);
        assert!(analyze_member_path("C:\\Windows\\x").absolute);
        assert!(analyze_member_path("../../etc/passwd").escape);
        assert!(analyze_member_path("a/../../b").escape);
        assert!(!analyze_member_path("a/../b").escape);
        assert!(analyze_member_path("a/../b").traversal);
    }

    #[test]
    fn resolves_link_targets() {
        let target = analyze_link_target("usr/lib/libz.so", "../../../etc/passwd");
        assert!(target.escape);
        assert_eq!(target.resolved, "../etc/passwd");
        let target = analyze_link_target("usr/lib/libz.so", "libz.so.1");
        assert_eq!(target.resolved, "usr/lib/libz.so.1");
        let target = analyze_hardlink_target("bin/agent");
        assert_eq!(target.resolved, "bin/agent");
        assert!(!target.escape);
    }

    #[test]
    fn rejects_unsafe_fixture_paths() {
        let root = Path::new("/tmp/fixtures");
        assert!(safe_join(root, "../outside").is_err());
        assert!(safe_join(root, "/etc/passwd").is_err());
        assert!(safe_join(root, "archives/a.zip").is_ok());
    }
}
