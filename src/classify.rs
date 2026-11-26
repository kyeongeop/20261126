//! Determine the [`TargetType`] of a path from its bytes and file name.

use crate::model::TargetType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    Elf,
    Archive,
    Other,
}

/// Inspect only the leading magic bytes. Never errors.
pub fn content_kind(data: &[u8]) -> ContentKind {
    if data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        ContentKind::Elf
    } else if data.starts_with(b"!<arch>\n") || data.starts_with(b"!<thin>\n") {
        ContentKind::Archive
    } else {
        ContentKind::Other
    }
}

/// Read `e_type` from an ELF header while respecting `EI_DATA`.
/// Returns `None` when the buffer is too short or not ELF.
pub fn elf_e_type(data: &[u8]) -> Option<u16> {
    if data.len() < 18 || !data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return None;
    }
    let little_endian = match data.get(5) {
        Some(1) => true,
        Some(2) => false,
        _ => return None,
    };
    let bytes: [u8; 2] = data.get(16..18)?.try_into().ok()?;
    Some(if little_endian {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

/// Name-only hint. Useful before parsing and for manifest entries.
pub fn classify_by_name(path: &str) -> Option<TargetType> {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();

    if name.ends_with(".a") || name.ends_with(".lib") || name.ends_with(".rlib") {
        return Some(TargetType::StaticLibrary);
    }
    if name.ends_with(".o") || name.ends_with(".obj") {
        return Some(TargetType::Relocatable);
    }
    if name.ends_with(".so")
        || name.contains(".so.")
        || name.ends_with(".dylib")
        || name.ends_with(".dll")
    {
        return Some(TargetType::SharedLibrary);
    }
    if name.ends_with(".exe") {
        return Some(TargetType::Executable);
    }
    None
}

/// Classify an ELF object using header facts plus the path.
pub fn classify_elf(
    e_type: Option<u16>,
    has_interp: bool,
    has_soname: bool,
    path: &str,
) -> TargetType {
    if let Some(TargetType::Relocatable) = name_relocatable(path) {
        // An explicit `.o` is always treated as relocatable, even if a
        // toolchain emitted another e_type.
        return TargetType::Relocatable;
    }

    match e_type {
        Some(ET_REL) => TargetType::Relocatable,
        Some(ET_EXEC) => TargetType::Executable,
        Some(ET_DYN) => {
            if let Some(kind) = classify_by_name(path) {
                return kind;
            }
            if has_soname && !has_interp {
                TargetType::SharedLibrary
            } else if has_interp {
                TargetType::Executable
            } else if has_soname {
                TargetType::SharedLibrary
            } else {
                // Position-independent object without loader metadata;
                // default to executable as the release primary target.
                TargetType::Executable
            }
        }
        _ => classify_by_name(path).unwrap_or(TargetType::Other),
    }
}

fn name_relocatable(path: &str) -> Option<TargetType> {
    matches!(classify_by_name(path), Some(TargetType::Relocatable))
        .then_some(TargetType::Relocatable)
}

/// Classify an archive. Archives are static libraries by definition here.
pub fn classify_archive(path: &str) -> TargetType {
    match classify_by_name(path) {
        Some(TargetType::Relocatable) => TargetType::Relocatable,
        _ => TargetType::StaticLibrary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_detects_elf_and_ar() {
        assert_eq!(content_kind(b"\x7fELF\x02\x01"), ContentKind::Elf);
        assert_eq!(content_kind(b"!<arch>\n"), ContentKind::Archive);
        assert_eq!(content_kind(b"hello world"), ContentKind::Other);
    }

    #[test]
    fn names_map_to_types() {
        assert_eq!(
            classify_by_name("a/b/libx.so.1"),
            Some(TargetType::SharedLibrary)
        );
        assert_eq!(classify_by_name("libx.a"), Some(TargetType::StaticLibrary));
        assert_eq!(classify_by_name("x.o"), Some(TargetType::Relocatable));
        assert_eq!(classify_by_name("x.exe"), Some(TargetType::Executable));
        assert_eq!(classify_by_name("bin/app_hardened"), None);
    }

    #[test]
    fn dyn_with_interp_is_pie_executable() {
        assert_eq!(
            classify_elf(Some(ET_DYN), true, false, "fixtures/bin/app_hardened"),
            TargetType::Executable
        );
        assert_eq!(
            classify_elf(Some(ET_DYN), false, true, "fixtures/lib/x.so"),
            TargetType::SharedLibrary
        );
        assert_eq!(
            classify_elf(Some(ET_EXEC), true, false, "app_weak"),
            TargetType::Executable
        );
    }
}
