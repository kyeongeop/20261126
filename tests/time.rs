use release_signature_admission::error::E_INVALID_TIMESTAMP;
use release_signature_admission::time::Timestamp;

#[test]
fn rfc3339_offsets_and_dates_resolve_to_utc() {
    let utc = Timestamp::parse("2026-11-26T10:00:00Z").unwrap();
    let offset = Timestamp::parse("2026-11-26T18:00:00+08:00").unwrap();
    let date = Timestamp::parse("2026-11-26").unwrap();

    assert_eq!(utc, offset);
    assert_eq!(date.unix_seconds(), utc.unix_seconds() - 10 * 60 * 60);
}

#[test]
fn calendar_and_non_ascii_inputs_fail_with_stable_code() {
    for invalid in [
        "2025-02-29T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-11-26T25:00:00Z",
        "2026-11-26T10:00:00",
        "二〇二六年十一月二十六日",
    ] {
        let error = Timestamp::parse(invalid).unwrap_err();
        assert_eq!(error.code(), E_INVALID_TIMESTAMP, "{invalid}");
    }
}
