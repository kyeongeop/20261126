//! POSIX ustar / GNU tar reader with PAX and long-name support.

use crate::archive::{Member, MemberKind, ParseFinding};
use crate::codes::IssueCode;
use crate::inflate::{MAX_MEMBERS, MAX_OUTPUT_BYTES, MAX_TOTAL_OUTPUT_BYTES};

#[derive(Debug, Default)]
struct Pending {
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
    size: Option<u64>,
}

pub fn parse_tar(bytes: &[u8]) -> Result<(Vec<Member>, Vec<ParseFinding>), String> {
    let mut members = Vec::new();
    let mut findings = Vec::new();
    let mut offset = 0usize;
    let mut pending = Pending::default();
    let mut saw_header = false;
    let mut total_uncompressed = 0usize;

    while offset + 512 <= bytes.len() {
        if members.len() >= MAX_MEMBERS {
            return Err("tar archive contains too many members".to_string());
        }
        let header = &bytes[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        if !checksum_matches(header) {
            return Err(format!("invalid tar header checksum at offset {offset}"));
        }
        saw_header = true;
        let typeflag = header[156];
        let header_size = parse_number(&header[124..136]).unwrap_or(0);
        let effective_size = if matches!(typeflag, b'L' | b'K' | b'x' | b'g') {
            header_size
        } else {
            pending.size.unwrap_or(header_size)
        };
        let effective_size = usize::try_from(effective_size)
            .map_err(|_| "tar member size is too large".to_string())?;
        let data_start = offset + 512;
        let data_end = data_start
            .checked_add(effective_size)
            .ok_or_else(|| "tar member size overflow".to_string())?;
        if data_end > bytes.len() {
            return Err("tar member data is truncated".to_string());
        }
        let data = &bytes[data_start..data_end];
        total_uncompressed = total_uncompressed
            .checked_add(effective_size)
            .ok_or_else(|| "tar total size overflow".to_string())?;
        if total_uncompressed > MAX_TOTAL_OUTPUT_BYTES {
            return Err("tar uncompressed content exceeds the total size limit".to_string());
        }
        let padded = data_end
            .checked_add(padding(effective_size))
            .ok_or_else(|| "tar member padding overflow".to_string())?;
        if padded > bytes.len() {
            return Err("tar member padding is truncated".to_string());
        }

        if typeflag == b'L' {
            pending.path = Some(c_string_bytes(data));
            offset = padded;
            continue;
        }
        if typeflag == b'K' {
            pending.linkpath = Some(c_string_bytes(data));
            offset = padded;
            continue;
        }
        if typeflag == b'x' {
            parse_pax(data, &mut pending)?;
            offset = padded;
            continue;
        }
        if typeflag == b'g' {
            offset = padded;
            continue;
        }

        let (raw_name, utf8) = match pending.path.take() {
            Some(bytes) => decode_bytes(&bytes),
            None => decode_bytes(&header_name_bytes(header)),
        };
        let link_target = if matches!(typeflag, b'1' | b'2') {
            Some(match pending.linkpath.take() {
                Some(bytes) => decode_bytes(&bytes).0,
                None => decode_bytes(&header_linkname_bytes(header)).0,
            })
        } else {
            pending.linkpath.take();
            None
        };
        let mut size = pending.size.take().unwrap_or(header_size);
        let mode = parse_number(&header[100..108]).unwrap_or(0) as u32 & 0o7777;
        let kind = classify(typeflag, raw_name.as_str());
        let member_index = members.len();
        if !utf8 {
            findings.push(ParseFinding::new(
                IssueCode::NonUtf8Path,
                Some(member_index),
                Some(&raw_name),
                "tar member name is not valid UTF-8",
            ));
        }
        if size > MAX_OUTPUT_BYTES as u64 {
            findings.push(ParseFinding::new(
                IssueCode::MemberContentError,
                Some(member_index),
                Some(&raw_name),
                "tar member exceeds the configured size limit",
            ));
            size = 0;
        }
        let mut data_vec = None;
        if kind == MemberKind::File {
            let amount = usize::try_from(size)
                .map_err(|_| "tar member size is too large".to_string())?
                .min(data.len());
            data_vec = Some(data[..amount].to_vec());
        } else {
            size = 0;
        }
        members.push(Member {
            index: member_index,
            raw_name: raw_name.clone(),
            name: raw_name,
            kind,
            mode: Some(mode),
            unix_mode: true,
            size,
            compressed_size: None,
            link_target,
            data: data_vec,
            encrypted: false,
        });
        offset = padded;
    }

    if !saw_header {
        return Err("tar archive has no headers".to_string());
    }
    Ok((members, findings))
}

fn classify(typeflag: u8, name: &str) -> MemberKind {
    match typeflag {
        b'0' | 0 | b'7' if name.ends_with('/') => MemberKind::Directory,
        b'0' | 0 | b'7' => MemberKind::File,
        b'1' => MemberKind::HardLink,
        b'2' => MemberKind::Symlink,
        b'3' => MemberKind::CharacterDevice,
        b'4' => MemberKind::BlockDevice,
        b'5' => MemberKind::Directory,
        b'6' => MemberKind::Fifo,
        _ => MemberKind::Other,
    }
}

fn header_name_bytes(header: &[u8]) -> Vec<u8> {
    let name = trim_nul(&header[..100]);
    let prefix = trim_nul(&header[345..500]);
    let is_ustar = header[257..262] == *b"ustar";
    if is_ustar && !prefix.is_empty() {
        let mut combined = prefix.to_vec();
        combined.push(b'/');
        combined.extend_from_slice(name);
        combined
    } else {
        name.to_vec()
    }
}

fn header_linkname_bytes(header: &[u8]) -> Vec<u8> {
    trim_nul(&header[157..257]).to_vec()
}

fn trim_nul(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    &bytes[..end]
}

fn c_string_bytes(bytes: &[u8]) -> Vec<u8> {
    trim_nul(bytes).to_vec()
}

fn decode_bytes(bytes: &[u8]) -> (String, bool) {
    match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_string(), true),
        Err(_) => (String::from_utf8_lossy(bytes).into_owned(), false),
    }
}

fn checksum_matches(header: &[u8]) -> bool {
    let stored = parse_number(&header[148..156]).unwrap_or(0);
    let mut sum = 0u64;
    for (index, byte) in header.iter().enumerate() {
        sum += if (148..156).contains(&index) {
            u64::from(b' ')
        } else {
            u64::from(*byte)
        };
    }
    sum == stored
}

fn parse_number(field: &[u8]) -> Option<u64> {
    if field.is_empty() {
        return None;
    }
    if field[0] & 0x80 != 0 {
        let mut value = u64::from(field[0] & 0x7f);
        for byte in &field[1..] {
            value = value.checked_mul(256)?.checked_add(u64::from(*byte))?;
        }
        return Some(value);
    }
    let text = String::from_utf8_lossy(field);
    let text = text.trim_matches(|character: char| character == ' ' || character == '\0');
    if text.is_empty() {
        return Some(0);
    }
    if !text.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) {
        return None;
    }
    u64::from_str_radix(text, 8).ok()
}

fn padding(size: usize) -> usize {
    (512 - (size % 512)) % 512
}

fn parse_pax(data: &[u8], pending: &mut Pending) -> Result<(), String> {
    let mut position = 0usize;
    while position < data.len() {
        if data[position] == 0 {
            break;
        }
        let space = data[position..]
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| "invalid PAX record length".to_string())?
            + position;
        let length_text = std::str::from_utf8(&data[position..space])
            .map_err(|_| "invalid PAX record length".to_string())?;
        let length = length_text
            .parse::<usize>()
            .map_err(|_| "invalid PAX record length".to_string())?;
        let end = position
            .checked_add(length)
            .ok_or_else(|| "PAX record length overflow".to_string())?;
        if length < 3 || end > data.len() {
            return Err("PAX record exceeds header data".to_string());
        }
        let record = &data[space + 1..end];
        if record.last() != Some(&b'\n') {
            return Err("PAX record is not newline terminated".to_string());
        }
        let record = &record[..record.len() - 1];
        if let Some(equals) = record.iter().position(|byte| *byte == b'=') {
            let key = &record[..equals];
            let value = &record[equals + 1..];
            match key {
                b"path" => pending.path = Some(value.to_vec()),
                b"linkpath" => pending.linkpath = Some(value.to_vec()),
                b"size" => {
                    let text =
                        std::str::from_utf8(value).map_err(|_| "invalid PAX size".to_string())?;
                    pending.size = Some(
                        text.parse::<u64>()
                            .map_err(|_| "invalid PAX size".to_string())?,
                    );
                }
                _ => {}
            }
        }
        position += length;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_octal_and_base256_numbers() {
        assert_eq!(parse_number(b"0000644\0"), Some(0o644));
        assert_eq!(parse_number(b"       \0"), Some(0));
        let mut base = [0u8; 12];
        base[0] = 0x80;
        base[11] = 42;
        assert_eq!(parse_number(&base), Some(42));
    }

    #[test]
    fn pads_to_blocks() {
        assert_eq!(padding(0), 0);
        assert_eq!(padding(1), 511);
        assert_eq!(padding(512), 0);
    }
}
