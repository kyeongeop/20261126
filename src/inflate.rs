//! Minimal RFC 1951 DEFLATE and RFC 1952 gzip reader.
//!
//! The project deliberately depends only on serde_json, sha2 and object, so
//! archive decompression is implemented here instead of adding flate2.  The
//! decoder is bounded and rejects malformed streams rather than panicking.

use crate::digest::crc32;

pub const MAX_OUTPUT_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_INPUT_BYTES: u64 = (MAX_OUTPUT_BYTES as u64) * 4;
pub const MAX_TOTAL_OUTPUT_BYTES: usize = MAX_OUTPUT_BYTES * 2;
pub const MAX_MEMBERS: usize = 100_000;

struct BitReader<'a> {
    data: &'a [u8],
    byte: usize,
    bit: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte: 0,
            bit: 0,
        }
    }

    fn read_bits(&mut self, count: u8) -> Result<u32, String> {
        if count > 32 {
            return Err("invalid bit count".to_string());
        }
        let mut value = 0u32;
        for index in 0..count {
            let byte = *self
                .data
                .get(self.byte)
                .ok_or_else(|| "unexpected end of deflate stream".to_string())?;
            let bit = (byte >> self.bit) & 1;
            value |= u32::from(bit) << index;
            self.bit += 1;
            if self.bit == 8 {
                self.bit = 0;
                self.byte += 1;
            }
        }
        Ok(value)
    }

    fn align_byte(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.byte += 1;
        }
    }

    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], String> {
        self.align_byte();
        let end = self
            .byte
            .checked_add(count)
            .ok_or_else(|| "deflate byte count overflow".to_string())?;
        let bytes = self
            .data
            .get(self.byte..end)
            .ok_or_else(|| "unexpected end of stored deflate block".to_string())?;
        self.byte = end;
        Ok(bytes)
    }
}

#[derive(Debug, Clone)]
struct Huffman {
    rings: Vec<Vec<(u32, u16)>>,
}

impl Huffman {
    fn from_lengths(lengths: &[u8]) -> Result<Self, String> {
        let mut counts = [0u16; 16];
        for length in lengths {
            if *length > 15 {
                return Err("deflate Huffman code is too long".to_string());
            }
            if *length > 0 {
                counts[*length as usize] += 1;
            }
        }
        let mut next_code = [0u32; 16];
        let mut code = 0u32;
        for bits in 1..=15 {
            code = (code + u32::from(counts[bits - 1])) << 1;
            next_code[bits] = code;
        }
        let mut rings: Vec<Vec<(u32, u16)>> = vec![Vec::new(); 16];
        for (symbol, length) in lengths.iter().enumerate() {
            let length = *length as usize;
            if length == 0 {
                continue;
            }
            let canonical = next_code[length];
            next_code[length] = next_code[length]
                .checked_add(1)
                .ok_or_else(|| "deflate Huffman code overflow".to_string())?;
            rings[length].push((reverse_bits(canonical, length as u8), symbol as u16));
        }
        Ok(Self { rings })
    }

    fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, String> {
        let mut code = 0u32;
        for (length, ring) in self.rings.iter().enumerate().take(16).skip(1) {
            code |= reader.read_bits(1)? << (length - 1);
            if let Some((_, symbol)) = ring.iter().find(|(candidate, _)| *candidate == code) {
                return Ok(*symbol);
            }
        }
        Err("invalid deflate Huffman code".to_string())
    }
}

fn reverse_bits(mut value: u32, length: u8) -> u32 {
    let mut reversed = 0u32;
    for _ in 0..length {
        reversed = (reversed << 1) | (value & 1);
        value >>= 1;
    }
    reversed
}

fn fixed_tables() -> (Huffman, Huffman) {
    let mut literal_lengths = vec![0u8; 288];
    for (symbol, length) in literal_lengths.iter_mut().enumerate() {
        *length = match symbol {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let distance_lengths = vec![5u8; 32];
    (
        Huffman::from_lengths(&literal_lengths).expect("fixed literal table is valid"),
        Huffman::from_lengths(&distance_lengths).expect("fixed distance table is valid"),
    )
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Decompress a raw DEFLATE stream.
pub fn inflate_raw(data: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let mut reader = BitReader::new(data);
    let mut output = Vec::new();
    loop {
        let final_block = reader.read_bits(1)? == 1;
        let block_type = reader.read_bits(2)?;
        match block_type {
            0 => inflate_stored(&mut reader, &mut output, limit)?,
            1 => {
                let (literals, distances) = fixed_tables();
                inflate_huffman(&mut reader, &mut output, limit, &literals, &distances)?;
            }
            2 => {
                let (literals, distances) = dynamic_tables(&mut reader)?;
                inflate_huffman(&mut reader, &mut output, limit, &literals, &distances)?;
            }
            _ => return Err("reserved deflate block type".to_string()),
        }
        if final_block {
            break;
        }
    }
    Ok(output)
}

fn inflate_stored(
    reader: &mut BitReader<'_>,
    output: &mut Vec<u8>,
    limit: usize,
) -> Result<(), String> {
    reader.align_byte();
    let length = reader.read_bits(16)? as usize;
    let complement = reader.read_bits(16)? as usize;
    if length != (!complement & 0xffff) {
        return Err("invalid stored deflate block length".to_string());
    }
    if output.len().saturating_add(length) > limit {
        return Err("decompressed archive exceeds size limit".to_string());
    }
    let bytes = reader.read_bytes(length)?.to_vec();
    output.extend_from_slice(&bytes);
    Ok(())
}

fn inflate_huffman(
    reader: &mut BitReader<'_>,
    output: &mut Vec<u8>,
    limit: usize,
    literals: &Huffman,
    distances: &Huffman,
) -> Result<(), String> {
    loop {
        let symbol = literals.decode(reader)?;
        match symbol {
            0..=255 => push_byte(output, symbol as u8, limit)?,
            256 => return Ok(()),
            257..=285 => {
                let index = (symbol - 257) as usize;
                let length = usize::from(LENGTH_BASE[index])
                    + reader.read_bits(LENGTH_EXTRA[index])? as usize;
                let distance_symbol = distances.decode(reader)? as usize;
                if distance_symbol >= DISTANCE_BASE.len() {
                    return Err("invalid deflate distance symbol".to_string());
                }
                let distance = usize::from(DISTANCE_BASE[distance_symbol])
                    + reader.read_bits(DISTANCE_EXTRA[distance_symbol])? as usize;
                if distance == 0 || distance > output.len() {
                    return Err("deflate distance points before output".to_string());
                }
                if output.len().saturating_add(length) > limit {
                    return Err("decompressed archive exceeds size limit".to_string());
                }
                for _ in 0..length {
                    let byte = output[output.len() - distance];
                    output.push(byte);
                }
            }
            _ => return Err("invalid deflate literal/length symbol".to_string()),
        }
    }
}

fn push_byte(output: &mut Vec<u8>, byte: u8, limit: usize) -> Result<(), String> {
    if output.len() >= limit {
        return Err("decompressed archive exceeds size limit".to_string());
    }
    output.push(byte);
    Ok(())
}

fn dynamic_tables(reader: &mut BitReader<'_>) -> Result<(Huffman, Huffman), String> {
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let literal_count = reader.read_bits(5)? as usize + 257;
    let distance_count = reader.read_bits(5)? as usize + 1;
    let code_count = reader.read_bits(4)? as usize + 4;
    if literal_count > 288 || distance_count > 32 {
        return Err("invalid dynamic deflate table size".to_string());
    }

    let mut code_lengths = [0u8; 19];
    for index in 0..code_count {
        code_lengths[ORDER[index]] = reader.read_bits(3)? as u8;
    }
    let code_table = Huffman::from_lengths(&code_lengths)?;

    let total = literal_count + distance_count;
    let mut lengths = Vec::with_capacity(total);
    while lengths.len() < total {
        let symbol = code_table.decode(reader)?;
        match symbol {
            0..=15 => lengths.push(symbol as u8),
            16 => {
                let previous = *lengths
                    .last()
                    .ok_or_else(|| "deflate repeat has no previous length".to_string())?;
                let repeat = 3 + reader.read_bits(2)? as usize;
                for _ in 0..repeat {
                    lengths.push(previous);
                }
            }
            17 => {
                let repeat = 3 + reader.read_bits(3)? as usize;
                lengths.extend(std::iter::repeat(0).take(repeat));
            }
            18 => {
                let repeat = 11 + reader.read_bits(7)? as usize;
                lengths.extend(std::iter::repeat(0).take(repeat));
            }
            _ => return Err("invalid deflate code-length symbol".to_string()),
        }
        if lengths.len() > total {
            return Err("deflate code-length repeat overruns table".to_string());
        }
    }

    let literals = Huffman::from_lengths(&lengths[..literal_count])?;
    let distances = Huffman::from_lengths(&lengths[literal_count..])?;
    Ok((literals, distances))
}

/// Returns true when the bytes start with the gzip magic.
pub fn is_gzip(data: &[u8]) -> bool {
    data.starts_with(&[0x1f, 0x8b])
}

/// Decompress a single-member gzip stream and verify its trailer.
pub fn gunzip(data: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    if !is_gzip(data) {
        return Err("not a gzip stream".to_string());
    }
    if data.len() < 18 {
        return Err("truncated gzip header".to_string());
    }
    if data[2] != 8 {
        return Err("gzip compression method is not deflate".to_string());
    }
    let flags = data[3];
    if flags & 0xe0 != 0 {
        return Err("gzip with reserved header flags is not supported".to_string());
    }
    let mut position = 10usize;
    if flags & 0x04 != 0 {
        if position + 2 > data.len() {
            return Err("truncated gzip extra field".to_string());
        }
        let length = u16::from_le_bytes([data[position], data[position + 1]]) as usize;
        position = position
            .checked_add(2 + length)
            .ok_or_else(|| "gzip extra field overflow".to_string())?;
        if position > data.len() {
            return Err("truncated gzip extra field".to_string());
        }
    }
    if flags & 0x08 != 0 {
        position = skip_c_string(data, position)?;
    }
    if flags & 0x10 != 0 {
        position = skip_c_string(data, position)?;
    }
    if flags & 0x02 != 0 {
        position = position
            .checked_add(2)
            .ok_or_else(|| "gzip header CRC overflow".to_string())?;
    }
    if position + 8 > data.len() {
        return Err("truncated gzip header".to_string());
    }
    let trailer = &data[data.len() - 8..];
    let expected_crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let expected_size =
        u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]) as usize;
    let output = inflate_raw(&data[position..data.len() - 8], limit)?;
    if output.len() != expected_size {
        return Err("gzip uncompressed size mismatch".to_string());
    }
    if crc32(&output) != expected_crc {
        return Err("gzip CRC mismatch".to_string());
    }
    Ok(output)
}

fn skip_c_string(data: &[u8], mut position: usize) -> Result<usize, String> {
    while position < data.len() {
        let byte = data[position];
        position += 1;
        if byte == 0 {
            return Ok(position);
        }
    }
    Err("unterminated gzip header string".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inflates_stored_block() {
        let data = [0x01, 0x03, 0x00, 0xfc, 0xff, b'a', b'b', b'c'];
        assert_eq!(inflate_raw(&data, 16).unwrap(), b"abc");
    }

    #[test]
    fn rejects_bad_stored_length() {
        let data = [0x01, 0x03, 0x00, 0x00, 0x00, b'a', b'b', b'c'];
        assert!(inflate_raw(&data, 16).is_err());
    }

    #[test]
    fn decompresses_repository_gzip_fixture() {
        let data = include_bytes!("../fixtures/archives/agent-2.4.0.tar.gz");
        let expanded = gunzip(data, MAX_OUTPUT_BYTES).expect("gzip fixture");
        assert!(expanded.starts_with(b"bin/"));
        assert!(expanded.len() > 10_000);
    }
}
