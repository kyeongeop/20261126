//! Object-file metadata used to explain binary members and permission risks.

use object::Object;
use serde_json::{json, Value};

use crate::digest::hex_lower;

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub format: String,
    pub architecture: String,
    pub kind: String,
    pub is_64: bool,
    pub endianness: String,
    pub build_id: Option<String>,
    pub executable: bool,
}

impl ObjectInfo {
    pub fn to_json(&self) -> Value {
        json!({
            "format": self.format,
            "architecture": self.architecture,
            "kind": self.kind,
            "is_64": self.is_64,
            "endianness": self.endianness,
            "build_id": self.build_id,
            "executable": self.executable,
        })
    }
}

/// Parse a member with `object`.  Data that is not an object file returns
/// `None`; this is normal for scripts, text and configuration members.
pub fn inspect_member(name: &str, bytes: &[u8]) -> Option<ObjectInfo> {
    let file = object::File::parse(bytes).ok()?;
    let kind = file.kind();
    let kind_name = format!("{kind:?}").to_ascii_lowercase();
    let executable =
        kind_name == "executable" || (kind_name == "dynamic" && !looks_like_shared_library(name));
    Some(ObjectInfo {
        format: format!("{:?}", file.format()).to_ascii_lowercase(),
        architecture: format!("{:?}", file.architecture()).to_ascii_lowercase(),
        kind: kind_name,
        is_64: file.is_64(),
        endianness: format!("{:?}", file.endianness()).to_ascii_lowercase(),
        build_id: file
            .build_id()
            .ok()
            .flatten()
            .map(hex_lower)
            .filter(|id| !id.is_empty()),
        executable,
    })
}

pub fn has_binary_extension(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".so", ".dylib", ".dll", ".exe", ".o", ".elf", ".bin"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
        || lower.contains(".so.")
}

pub fn looks_like_shared_library(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".so")
        || lower.contains(".so.")
        || lower.ends_with(".dylib")
        || lower.ends_with(".dll")
}

pub fn has_shebang(bytes: &[u8]) -> bool {
    bytes.starts_with(b"#!")
}

pub fn looks_like_elf_or_pe_or_macho(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"MZ")
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
}
