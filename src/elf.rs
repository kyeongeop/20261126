//! 基于 `object` 的 ELF 动态段解析，提取 NEEDED / SONAME / RPATH / RUNPATH。
//!
//! 同时支持带节区表与被 strip（仅程序头）的 ELF：优先走 SHT_DYNAMIC 节区，
//! 失败时回退到 PT_DYNAMIC 段并通过 DT_STRTAB 虚拟地址定位动态字符串表。

use crate::errors::{code, RiskError, RiskResult};
use object::Endianness;
use object::elf;
use object::read::elf::{
    Dyn, ElfFile, ElfFile32, ElfFile64, FileHeader, ProgramHeader, SectionHeader,
};
use object::read::{FileKind, SectionIndex, StringTable};
use sha2::{Digest, Sha256};

/// ELF 解析得到的原始动态信息，变量展开在 analyzer 中完成。
#[derive(Debug, Clone, Default)]
pub struct ElfDynamicInfo {
    pub class: String,
    pub machine: String,
    pub elf_type: String,
    pub sha256: String,
    pub soname: Option<String>,
    pub needed: Vec<String>,
    pub rpath_raw: Option<String>,
    pub runpath_raw: Option<String>,
}

pub fn parse_elf(bytes: &[u8]) -> RiskResult<ElfDynamicInfo> {
    if bytes.len() < 4 || &bytes[0..4] != b"\x7fELF" {
        return Err(RiskError::new(code::NOT_ELF, "文件不是 ELF 格式"));
    }
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = format!("{:x}", hasher.finalize());

    let mut info = match FileKind::parse(bytes) {
        Ok(FileKind::Elf32) => {
            let file: ElfFile<'_, object::elf::FileHeader32<Endianness>> =
                ElfFile32::parse(bytes)
                .map_err(|e| RiskError::new(code::ELF_PARSE, format!("ELF 解析失败: {e}")))?;
            parse_inner(file, bytes, &digest)?
        }
        Ok(FileKind::Elf64) => {
            let file: ElfFile<'_, object::elf::FileHeader64<Endianness>> =
                ElfFile64::parse(bytes)
                .map_err(|e| RiskError::new(code::ELF_PARSE, format!("ELF 解析失败: {e}")))?;
            parse_inner(file, bytes, &digest)?
        }
        Ok(_) => {
            return Err(RiskError::new(code::NOT_ELF, "文件不是 ELF 格式"));
        }
        Err(e) => {
            return Err(RiskError::new(code::ELF_PARSE, format!("ELF 解析失败: {e}")));
        }
    };
    info.sha256 = digest;
    Ok(info)
}

fn parse_inner<Elf>(
    file: ElfFile<'_, Elf>,
    bytes: &[u8],
    digest: &str,
) -> RiskResult<ElfDynamicInfo>
where
    Elf: FileHeader,
{
    let endian = file.endian();
    let header = file.elf_header();

    let mut info = ElfDynamicInfo {
        sha256: digest.to_string(),
        class: class_name(header.is_class_64()),
        machine: machine_name(header.e_machine(endian)),
        elf_type: type_name(header.e_type(endian)),
        ..ElfDynamicInfo::default()
    };

    let (entries, strings) = dynamic_entries(&file, bytes)?;
    for entry in entries {
        let tag = match entry.tag32(endian) {
            Some(tag) => tag,
            None => continue,
        };
        if tag == elf::DT_NULL {
            break;
        }
        if !entry.is_string(endian) {
            continue;
        }
        let value = entry
            .string(endian, strings)
            .map_err(|e| RiskError::new(code::DYNAMIC_SECTION, format!("动态字符串读取失败: {e}")))?;
        let text = String::from_utf8_lossy(value).into_owned();
        match tag {
            elf::DT_NEEDED => info.needed.push(text),
            elf::DT_SONAME => info.soname = Some(text),
            elf::DT_RPATH => info.rpath_raw = Some(text),
            elf::DT_RUNPATH => info.runpath_raw = Some(text),
            _ => {}
        }
    }
    Ok(info)
}

/// 取出动态表项与对应字符串表。
fn dynamic_entries<'a, Elf>(
    file: &ElfFile<'a, Elf>,
    bytes: &'a [u8],
) -> RiskResult<(&'a [Elf::Dyn], StringTable<'a>)>
where
    Elf: FileHeader,
{
    let endian = file.endian();

    if let Some((dyns, str_index)) = file
        .elf_section_table()
        .dynamic(endian, bytes)
        .map_err(|e| RiskError::new(code::DYNAMIC_SECTION, format!("动态节区读取失败: {e}")))?
    {
        let strings = section_string_table(file, bytes, str_index)?;
        return Ok((dyns, strings));
    }

    // strip 后没有节区表：从 PT_DYNAMIC 段取表项，用 DT_STRTAB 地址反查段数据。
    for segment in file.elf_program_headers() {
        if let Some(dyns) = segment
            .dynamic(endian, bytes)
            .map_err(|e| RiskError::new(code::DYNAMIC_SECTION, format!("动态段读取失败: {e}")))?
        {
            let mut strtab_addr = None;
            let mut strtab_size = 0u64;
            for entry in dyns {
                match entry.tag32(endian) {
                    Some(elf::DT_STRTAB) => strtab_addr = entry.val32(endian).map(u64::from),
                    Some(elf::DT_STRSZ) => {
                        strtab_size = entry.val32(endian).map(u64::from).unwrap_or(0)
                    }
                    _ => {}
                }
            }
            let strings = match strtab_addr {
                Some(addr) => {
                    let (offset, capped) =
                        strtab_from_segments(file.elf_program_headers(), endian, bytes, addr, strtab_size)?;
                    // 以整个文件为 ReadRef，窗口 [offset, offset+capped) 与
                    // DT_STRTAB 虚拟地址对应的文件区间一致；d_val 即该窗口内偏移。
                    StringTable::new(bytes, offset, offset + capped)
                }
                None => StringTable::default(),
            };
            return Ok((dyns, strings));
        }
    }

    // 静态链接或无动态段：返回空表，不视为错误。
    Ok((&[], StringTable::default()))
}

/// 直接按节区头构造动态字符串表。
///
/// `SectionTable::strings` 会把索引 0 视为空表，但 strip 后 `.dynstr`
/// 可能恰好位于索引 0，因此这里绕过该特判直接读取节区数据。
fn section_string_table<'a, Elf>(
    file: &ElfFile<'a, Elf>,
    bytes: &'a [u8],
    index: SectionIndex,
) -> RiskResult<StringTable<'a>>
where
    Elf: FileHeader,
{
    let endian = file.endian();
    let section = file
        .elf_section_table()
        .section(index)
        .map_err(|e| RiskError::new(code::DYNAMIC_SECTION, format!("动态字符串节区无效: {e}")))?;
    let data = section
        .data(endian, bytes)
        .map_err(|e| RiskError::new(code::DYNAMIC_SECTION, format!("动态字符串表读取失败: {e}")))?;
    Ok(StringTable::new(data, 0, data.len() as u64))
}

/// 根据 DT_STRTAB 虚拟地址在加载段中定位文件偏移与长度。
fn strtab_from_segments<P>(
    segments: &[P],
    endian: P::Endian,
    bytes: &[u8],
    addr: u64,
    size: u64,
) -> RiskResult<(u64, u64)>
where
    P: ProgramHeader,
{
    for segment in segments {
        let start = segment.p_vaddr(endian).into();
        let end = start + segment.p_filesz(endian).into();
        if addr >= start && addr < end {
            let offset = segment.p_offset(endian).into() + (addr - start);
            let capped = size.min(end.saturating_sub(addr));
            if offset + capped <= bytes.len() as u64 {
                return Ok((offset, capped));
            }
        }
    }
    Err(RiskError::new(
        code::DYNAMIC_SECTION,
        "无法在程序段中定位 DT_STRTAB",
    ))
}

fn class_name(is_64: bool) -> String {
    if is_64 {
        "ELF64".to_string()
    } else {
        "ELF32".to_string()
    }
}

fn machine_name(machine: u16) -> String {
    match machine {
        elf::EM_386 => "x86".to_string(),
        elf::EM_X86_64 => "x86_64".to_string(),
        elf::EM_AARCH64 => "aarch64".to_string(),
        elf::EM_ARM => "arm".to_string(),
        elf::EM_RISCV => "riscv".to_string(),
        other => format!("EM_{other}"),
    }
}

fn type_name(kind: u16) -> String {
    match kind {
        elf::ET_NONE => "ET_NONE".to_string(),
        elf::ET_REL => "ET_REL".to_string(),
        elf::ET_EXEC => "ET_EXEC".to_string(),
        elf::ET_DYN => "ET_DYN".to_string(),
        elf::ET_CORE => "ET_CORE".to_string(),
        other => format!("ET_{other}"),
    }
}
