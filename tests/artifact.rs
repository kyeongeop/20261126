use release_signature_admission::Artifact;
use std::fs;
use std::path::PathBuf;

#[test]
fn fixture_object_metadata_and_digest_are_extracted() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal_elf.hex");
    let hex = fs::read_to_string(path).unwrap();
    let bytes = decode_hex(&hex);
    let artifact = Artifact::from_bytes(&bytes);

    assert_eq!(artifact.size, Some(64));
    assert_eq!(artifact.sha256.len(), 64);
    let object = artifact.object.expect("fixture is a valid ELF object");
    assert_eq!(object.format, "elf");
    assert_eq!(object.architecture, "x86_64");
    assert!(object.is_64_bit);
    assert!(object.is_little_endian);
}

fn decode_hex(input: &str) -> Vec<u8> {
    let digits = input
        .bytes()
        .filter(|byte| byte.is_ascii_hexdigit())
        .collect::<Vec<_>>();
    assert_eq!(digits.len() % 2, 0);
    digits
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}
