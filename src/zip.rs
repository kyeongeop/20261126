//! Bounded ZIP reader for release archives.
//!
//! Names, Unix modes and symlink payloads come from the central directory.
//! Local headers are used only to locate member data; sizes and CRC values are
//! taken from the central directory so malformed local metadata cannot hide an
//! unsafe member from the tree walk.

use crate::archive::{Member, MemberKind, ParseFinding};
use crate::codes::IssueCode;
use crate::digest::crc32;
use crate::inflate::{inflate_raw, MAX_MEMBERS, MAX_OUTPUT_BYTES, MAX_TOTAL_OUTPUT_BYTES};

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;

#[derive(Debug, Clone, Copy)]
struct EndOfCentral {
    entries: u64,
    directory_offset: u64,
    directory_size: u64,
}

pub fn parse_zip(bytes: &[u8]) -> Result<(Vec<Member>, Vec<ParseFinding>), String> {
    let end = find_end_of_central(bytes)?;
    let mut members = Vec::new();
    let mut findings = Vec::new();
    let mut total_uncompressed = 0usize;
    let mut offset = usize::try_from(end.directory_offset)
        .map_err(|_| "ZIP central directory offset is too large".to_string())?;
    let directory_end = usize::try_from(
        end.directory_offset
            .checked_add(end.directory_size)
            .ok_or_else(|| "ZIP central directory size overflow".to_string())?,
    )
    .map_err(|_| "ZIP central directory size is too large".to_string())?;
    for _ in 0..end.entries {
        if members.len() >= MAX_MEMBERS {
            return Err("ZIP archive contains too many members".to_string());
        }
        if offset + 46 > bytes.len() || offset >= directory_end {
            return Err("truncated ZIP central directory".to_string());
        }
        if le_u32(bytes, offset)? != CENTRAL_SIGNATURE {
            return Err("invalid ZIP central directory signature".to_string());
        }
        let made_by = le_u16(bytes, offset + 4)?;
        let flags = le_u16(bytes, offset + 8)?;
        let method = le_u16(bytes, offset + 10)?;
        let expected_crc = le_u32(bytes, offset + 16)?;
        let compressed_size = le_u32(bytes, offset + 20)?;
        let uncompressed_size = le_u32(bytes, offset + 24)?;
        let name_len = le_u16(bytes, offset + 28)? as usize;
        let extra_len = le_u16(bytes, offset + 30)? as usize;
        let comment_len = le_u16(bytes, offset + 32)? as usize;
        let external_attributes = le_u32(bytes, offset + 38)?;
        let local_offset = le_u32(bytes, offset + 42)?;
        let name_start = offset + 46;
        let extra_start = name_start
            .checked_add(name_len)
            .ok_or_else(|| "ZIP name field overflow".to_string())?;
        let comment_start = extra_start
            .checked_add(extra_len)
            .ok_or_else(|| "ZIP extra field overflow".to_string())?;
        let next = comment_start
            .checked_add(comment_len)
            .ok_or_else(|| "ZIP comment field overflow".to_string())?;
        if next > bytes.len() {
            return Err("ZIP central directory member is truncated".to_string());
        }
        let name_bytes = &bytes[name_start..extra_start];
        let extra = &bytes[extra_start..comment_start];
        let (uncompressed_size, compressed_size, local_offset) =
            zip64_values(extra, uncompressed_size, compressed_size, local_offset)?;
        let member_index = members.len();
        let (raw_name, utf8) = decode_name(name_bytes, flags);
        if !utf8 {
            findings.push(ParseFinding::new(
                IssueCode::NonUtf8Path,
                Some(member_index),
                Some(&raw_name),
                "ZIP member name is not valid UTF-8",
            ));
        }
        let (kind, mode, unix_mode) =
            classify_mode(raw_name.as_str(), external_attributes, made_by);
        let mut member = Member {
            index: member_index,
            raw_name: raw_name.clone(),
            name: raw_name,
            kind,
            mode,
            unix_mode,
            size: uncompressed_size,
            compressed_size: Some(compressed_size),
            link_target: None,
            data: None,
            encrypted: flags & 0x0001 != 0,
        };
        if member.encrypted {
            findings.push(ParseFinding::new(
                IssueCode::EncryptedMember,
                Some(member_index),
                Some(&member.name),
                "ZIP member is encrypted and cannot be inspected",
            ));
        } else {
            let local_offset = usize::try_from(local_offset)
                .map_err(|_| "ZIP local header offset is too large".to_string())?;
            match read_member_data(
                bytes,
                local_offset,
                compressed_size,
                uncompressed_size,
                method,
            ) {
                Ok(data) => {
                    if crc32(&data) != expected_crc {
                        findings.push(ParseFinding::new(
                            IssueCode::CrcMismatch,
                            Some(member_index),
                            Some(&member.name),
                            "ZIP member CRC does not match the central directory",
                        ));
                    }
                    member.size = data.len() as u64;
                    total_uncompressed = total_uncompressed
                        .checked_add(data.len())
                        .ok_or_else(|| "ZIP total size overflow".to_string())?;
                    if total_uncompressed > MAX_TOTAL_OUTPUT_BYTES {
                        return Err(
                            "ZIP uncompressed content exceeds the total size limit".to_string()
                        );
                    }
                    if member.kind == MemberKind::Symlink {
                        member.link_target = Some(String::from_utf8_lossy(&data).into_owned());
                    } else {
                        member.data = Some(data);
                    }
                }
                Err(message) => findings.push(ParseFinding::new(
                    IssueCode::MemberContentError,
                    Some(member_index),
                    Some(&member.name),
                    message,
                )),
            }
        }
        members.push(member);
        offset = next;
    }
    Ok((members, findings))
}

fn find_end_of_central(bytes: &[u8]) -> Result<EndOfCentral, String> {
    if bytes.len() < 22 {
        return Err("ZIP archive is too short".to_string());
    }
    let earliest = bytes.len().saturating_sub(65_557);
    let mut eocd = None;
    for offset in (earliest..=bytes.len() - 22).rev() {
        if le_u32(bytes, offset).ok() == Some(EOCD_SIGNATURE) {
            let comment_len = le_u16(bytes, offset + 20)? as usize;
            if offset + 22 + comment_len == bytes.len() {
                eocd = Some(offset);
                break;
            }
        }
    }
    let eocd = eocd.ok_or_else(|| "ZIP end-of-central-directory record not found".to_string())?;
    let entries = le_u16(bytes, eocd + 10)? as u64;
    let directory_size = le_u32(bytes, eocd + 12)? as u64;
    let directory_offset = le_u32(bytes, eocd + 16)? as u64;
    let looks_zip64 =
        entries == 0xffff || directory_size == 0xffff_ffff || directory_offset == 0xffff_ffff;
    if !looks_zip64 {
        return Ok(EndOfCentral {
            entries,
            directory_offset,
            directory_size,
        });
    }
    let locator = eocd
        .checked_sub(20)
        .ok_or_else(|| "ZIP64 locator is missing".to_string())?;
    if le_u32(bytes, locator)? != ZIP64_LOCATOR_SIGNATURE {
        return Err("ZIP64 locator is missing".to_string());
    }
    let zip64_offset = le_u64(bytes, locator + 8)?;
    let zip64_offset = usize::try_from(zip64_offset)
        .map_err(|_| "ZIP64 end record offset is too large".to_string())?;
    if le_u32(bytes, zip64_offset)? != ZIP64_EOCD_SIGNATURE {
        return Err("ZIP64 end-of-central-directory record is missing".to_string());
    }
    Ok(EndOfCentral {
        entries: le_u64(bytes, zip64_offset + 32)?,
        directory_size: le_u64(bytes, zip64_offset + 40)?,
        directory_offset: le_u64(bytes, zip64_offset + 48)?,
    })
}

fn zip64_values(
    extra: &[u8],
    uncompressed: u32,
    compressed: u32,
    local_offset: u32,
) -> Result<(u64, u64, u64), String> {
    let mut uncompressed = u64::from(uncompressed);
    let mut compressed = u64::from(compressed);
    let mut local_offset = u64::from(local_offset);
    if uncompressed != 0xffff_ffff && compressed != 0xffff_ffff && local_offset != 0xffff_ffff {
        return Ok((uncompressed, compressed, local_offset));
    }
    let mut position = 0usize;
    while position + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[position], extra[position + 1]]);
        let length = u16::from_le_bytes([extra[position + 2], extra[position + 3]]) as usize;
        let start = position + 4;
        let end = start
            .checked_add(length)
            .ok_or_else(|| "ZIP extra field overflow".to_string())?;
        if end > extra.len() {
            return Err("truncated ZIP extra field".to_string());
        }
        if id == 0x0001 {
            let mut cursor = start;
            if uncompressed == 0xffff_ffff {
                uncompressed = read_extra_u64(extra, &mut cursor, end)?;
            }
            if compressed == 0xffff_ffff {
                compressed = read_extra_u64(extra, &mut cursor, end)?;
            }
            if local_offset == 0xffff_ffff {
                local_offset = read_extra_u64(extra, &mut cursor, end)?;
            }
            break;
        }
        position = end;
    }
    Ok((uncompressed, compressed, local_offset))
}

fn read_extra_u64(extra: &[u8], cursor: &mut usize, end: usize) -> Result<u64, String> {
    let next = cursor
        .checked_add(8)
        .ok_or_else(|| "ZIP64 extra value overflow".to_string())?;
    if next > end {
        return Err("truncated ZIP64 extra value".to_string());
    }
    let value = le_u64(extra, *cursor)?;
    *cursor = next;
    Ok(value)
}

fn decode_name(bytes: &[u8], flags: u16) -> (String, bool) {
    match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_string(), true),
        Err(_) if flags & 0x0800 != 0 => (String::from_utf8_lossy(bytes).into_owned(), false),
        Err(_) => (String::from_utf8_lossy(bytes).into_owned(), false),
    }
}

fn classify_mode(name: &str, external: u32, made_by: u16) -> (MemberKind, Option<u32>, bool) {
    let unix = made_by >> 8 == 3;
    let raw_mode = if unix { external >> 16 } else { 0 };
    let file_type = raw_mode & 0xf000;
    let kind = match file_type {
        0x4000 => MemberKind::Directory,
        0xa000 => MemberKind::Symlink,
        0x8000 => MemberKind::File,
        0x2000 => MemberKind::CharacterDevice,
        0x6000 => MemberKind::BlockDevice,
        0x1000 => MemberKind::Fifo,
        0 if name.ends_with('/') => MemberKind::Directory,
        0 => MemberKind::File,
        _ => MemberKind::Other,
    };
    let mode = if unix && raw_mode != 0 {
        Some(raw_mode)
    } else {
        None
    };
    (kind, mode, unix && raw_mode != 0)
}

fn read_member_data(
    bytes: &[u8],
    local_offset: usize,
    compressed_size: u64,
    uncompressed_size: u64,
    method: u16,
) -> Result<Vec<u8>, String> {
    let header_end = local_offset
        .checked_add(30)
        .ok_or_else(|| "ZIP local header offset overflow".to_string())?;
    if header_end > bytes.len() || le_u32(bytes, local_offset)? != LOCAL_SIGNATURE {
        return Err("ZIP local header is missing or invalid".to_string());
    }
    let name_len = le_u16(bytes, local_offset + 26)? as usize;
    let extra_len = le_u16(bytes, local_offset + 28)? as usize;
    let start = header_end
        .checked_add(name_len)
        .and_then(|value| value.checked_add(extra_len))
        .ok_or_else(|| "ZIP local header offset overflow".to_string())?;
    let compressed_size = usize::try_from(compressed_size)
        .map_err(|_| "ZIP compressed member is too large".to_string())?;
    let end = start
        .checked_add(compressed_size)
        .ok_or_else(|| "ZIP member size overflow".to_string())?;
    let payload = bytes
        .get(start..end)
        .ok_or_else(|| "ZIP member data is truncated".to_string())?;
    let limit = usize::try_from(uncompressed_size)
        .unwrap_or(MAX_OUTPUT_BYTES)
        .min(MAX_OUTPUT_BYTES);
    match method {
        0 => {
            if payload.len() > limit {
                return Err("stored ZIP member exceeds size limit".to_string());
            }
            Ok(payload.to_vec())
        }
        8 => inflate_raw(payload, limit),
        other => Err(format!("unsupported ZIP compression method {other}")),
    }
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "unexpected end of ZIP data".to_string())?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| "unexpected end of ZIP data".to_string())?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn le_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| "unexpected end of ZIP64 data".to_string())?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}
