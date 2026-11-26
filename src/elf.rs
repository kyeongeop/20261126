//! Small, bounds-checked ELF structural parser.
//!
//! It extracts exactly the header/segment/dynamic facts needed for the
//! hardening checks. Symbol tables and archives are handled through the
//! `object` crate in [`crate::symbols`] and [`crate::archive`].

pub const PT_INTERP: u32 = 3;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;

pub const PF_X: u32 = 1;

pub const DT_NULL: u64 = 0;
pub const DT_BIND_NOW: u64 = 24;
pub const DT_FLAGS: u64 = 30;
pub const DT_SONAME: u64 = 14;
pub const DT_FLAGS_1: u64 = 0x6fff_fffb;

pub const DF_BIND_NOW: u64 = 0x8;
pub const DF_1_NOW: u64 = 0x1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_filesz: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ElfStructure {
    pub class: u8,
    pub little_endian: bool,
    pub e_type: u16,
    pub machine: u16,
    pub phdrs: Vec<Phdr>,
    /// Raw `(d_tag, d_val)` pairs until `DT_NULL`.
    pub dynamic: Vec<(u64, u64)>,
}

impl ElfStructure {
    pub fn has_interp(&self) -> bool {
        self.phdrs.iter().any(|p| p.p_type == PT_INTERP)
    }

    pub fn has_relro(&self) -> bool {
        self.phdrs.iter().any(|p| p.p_type == PT_GNU_RELRO)
    }

    pub fn gnu_stack_flags(&self) -> Option<u32> {
        self.phdrs
            .iter()
            .find(|p| p.p_type == PT_GNU_STACK)
            .map(|p| p.p_flags)
    }

    pub fn has_dynamic_segment(&self) -> bool {
        self.phdrs.iter().any(|p| p.p_type == PT_DYNAMIC)
    }

    pub fn has_soname(&self) -> bool {
        self.dynamic.iter().any(|(tag, _)| *tag == DT_SONAME)
    }

    pub fn bind_now(&self) -> bool {
        self.dynamic.iter().any(|(tag, val)| {
            *tag == DT_BIND_NOW
                || (*tag == DT_FLAGS && (*val & DF_BIND_NOW) != 0)
                || (*tag == DT_FLAGS_1 && (*val & DF_1_NOW) != 0)
        })
    }
}

struct Reader<'a> {
    data: &'a [u8],
    le: bool,
}

impl<'a> Reader<'a> {
    fn u16(&self, offset: usize) -> Option<u16> {
        let b: [u8; 2] = self.data.get(offset..offset + 2)?.try_into().ok()?;
        Some(if self.le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }

    fn u32(&self, offset: usize) -> Option<u32> {
        let b: [u8; 4] = self.data.get(offset..offset + 4)?.try_into().ok()?;
        Some(if self.le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    fn u64(&self, offset: usize) -> Option<u64> {
        let b: [u8; 8] = self.data.get(offset..offset + 8)?.try_into().ok()?;
        Some(if self.le {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }
}

/// Parse the structural ELF facts. Returns a stable-ish error message on
/// truncation; callers map it to [`crate::codes::E_ARTIFACT_PARSE`].
pub fn parse_structure(data: &[u8]) -> Result<ElfStructure, String> {
    if data.len() < 16 || !data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return Err("not an ELF object".to_string());
    }
    let class = data[4];
    let le = match data[5] {
        1 => true,
        2 => false,
        other => return Err(format!("unsupported EI_DATA={other}")),
    };
    if class != 1 && class != 2 {
        return Err(format!("unsupported EI_CLASS={class}"));
    }
    let r = Reader { data, le };

    let e_type = r.u16(16).ok_or("truncated e_type")?;
    let machine = r.u16(18).ok_or("truncated e_machine")?;

    let (phoff, phentsize, phnum): (u64, usize, usize) = if class == 2 {
        (
            r.u64(32).ok_or("truncated e_phoff")?,
            r.u16(54).ok_or("truncated e_phentsize")? as usize,
            r.u16(56).ok_or("truncated e_phnum")? as usize,
        )
    } else {
        (
            r.u32(28).ok_or("truncated e_phoff")? as u64,
            r.u16(42).ok_or("truncated e_phentsize")? as usize,
            r.u16(44).ok_or("truncated e_phnum")? as usize,
        )
    };

    let mut phdrs = Vec::new();
    if phoff != 0 && phnum > 0 {
        let ent = if phentsize == 0 {
            if class == 2 {
                56
            } else {
                32
            }
        } else {
            phentsize
        };
        for i in 0..phnum {
            let base = phoff as usize + i * ent;
            let ph = if class == 2 {
                Phdr {
                    p_type: r.u32(base).ok_or("truncated p_type")?,
                    p_flags: r.u32(base + 4).ok_or("truncated p_flags")?,
                    p_offset: r.u64(base + 8).ok_or("truncated p_offset")?,
                    p_filesz: r.u64(base + 32).ok_or("truncated p_filesz")?,
                }
            } else {
                Phdr {
                    p_type: r.u32(base).ok_or("truncated p_type")?,
                    p_offset: r.u32(base + 4).ok_or("truncated p_offset")? as u64,
                    p_filesz: r.u32(base + 16).ok_or("truncated p_filesz")? as u64,
                    p_flags: r.u32(base + 24).ok_or("truncated p_flags")?,
                }
            };
            phdrs.push(ph);
        }
    }

    let dynamic = parse_dynamic(data, &r, class, &phdrs);

    Ok(ElfStructure {
        class,
        little_endian: le,
        e_type,
        machine,
        phdrs,
        dynamic,
    })
}

fn parse_dynamic(data: &[u8], r: &Reader<'_>, class: u8, phdrs: &[Phdr]) -> Vec<(u64, u64)> {
    let Some(seg) = phdrs.iter().find(|p| p.p_type == PT_DYNAMIC) else {
        return Vec::new();
    };
    let start = seg.p_offset as usize;
    let size = seg.p_filesz as usize;
    let Some(region) = data.get(start..start.saturating_add(size)) else {
        return Vec::new();
    };
    let ent = if class == 2 { 16 } else { 8 };
    let mut out = Vec::new();
    let mut offset = 0;
    while offset + ent <= region.len() {
        let (tag, val) = if class == 2 {
            let Some(tag) = r.u64(start + offset) else {
                break;
            };
            let Some(val) = r.u64(start + offset + 8) else {
                break;
            };
            (tag, val)
        } else {
            let Some(tag32) = r.u32(start + offset) else {
                break;
            };
            let Some(val32) = r.u32(start + offset + 4) else {
                break;
            };
            (tag32 as u64, val32 as u64)
        };
        if tag == DT_NULL {
            break;
        }
        out.push((tag, val));
        offset += ent;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        assert!(parse_structure(b"not an elf at all").is_err());
    }

    #[test]
    fn truncated_elf_is_error_not_panic() {
        // ELF magic + 64-bit little-endian ident, then almost nothing.
        let mut bytes = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        bytes.resize(96, 0);
        // Point at a 56-byte phdr table right after the header and claim
        // many entries; the truncated buffer must yield a safe error.
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(parse_structure(&bytes).is_err());
    }
}
