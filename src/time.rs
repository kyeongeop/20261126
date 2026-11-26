use crate::error::{AdmissionError, E_INVALID_TIMESTAMP};
use serde_json::Value;

/// A UTC instant represented as whole seconds since the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    seconds: i64,
}

impl Timestamp {
    pub const fn from_unix_seconds(seconds: i64) -> Self {
        Self { seconds }
    }

    pub const fn unix_seconds(self) -> i64 {
        self.seconds
    }

    /// Parse RFC3339 with a mandatory or numeric timezone, or an ISO date.
    pub fn parse(input: &str) -> Result<Self, AdmissionError> {
        let input = input.trim();
        if input.len() < 10 || !input.is_ascii() {
            return Err(invalid(input, "expected YYYY-MM-DD or RFC3339"));
        }

        let year = number(&input[0..4], input, "year")?;
        if &input[4..5] != "-" {
            return Err(invalid(input, "expected '-' after year"));
        }
        let month = number(&input[5..7], input, "month")?;
        if &input[7..8] != "-" {
            return Err(invalid(input, "expected '-' after month"));
        }
        let day = number(&input[8..10], input, "day")?;
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return Err(invalid(input, "invalid calendar date"));
        }
        if input.len() == 10 {
            return Ok(Self::from_unix_seconds(
                days_from_civil(year, month, day) * 86_400,
            ));
        }

        if !matches!(&input[10..11], "T" | "t" | " ") || input.len() < 19 {
            return Err(invalid(input, "expected 'T' and HH:MM:SS"));
        }
        let hour = number(&input[11..13], input, "hour")?;
        if &input[13..14] != ":" {
            return Err(invalid(input, "expected ':' after hour"));
        }
        let minute = number(&input[14..16], input, "minute")?;
        if &input[16..17] != ":" {
            return Err(invalid(input, "expected ':' after minute"));
        }
        let second = number(&input[17..19], input, "second")?;
        if hour > 23 || minute > 59 || second > 60 {
            return Err(invalid(input, "invalid clock time"));
        }

        let mut cursor = 19;
        if input[cursor..].starts_with('.') {
            cursor += 1;
            let start = cursor;
            while cursor < input.len() && input.as_bytes()[cursor].is_ascii_digit() {
                cursor += 1;
            }
            if cursor == start {
                return Err(invalid(input, "empty fractional seconds"));
            }
        }

        let offset_seconds = if input[cursor..].eq_ignore_ascii_case("Z") {
            cursor += 1;
            0
        } else if cursor + 6 == input.len()
            && matches!(&input[cursor..cursor + 1], "+" | "-")
            && &input[cursor + 3..cursor + 4] == ":"
        {
            let sign = if &input[cursor..cursor + 1] == "-" {
                -1
            } else {
                1
            };
            let offset_hour = number(&input[cursor + 1..cursor + 3], input, "UTC offset hour")?;
            let offset_minute = number(&input[cursor + 4..cursor + 6], input, "UTC offset minute")?;
            if offset_hour > 23 || offset_minute > 59 {
                return Err(invalid(input, "invalid UTC offset"));
            }
            cursor += 6;
            sign * (offset_hour * 3_600 + offset_minute * 60)
        } else {
            return Err(invalid(input, "missing or invalid timezone"));
        };

        if cursor != input.len() {
            return Err(invalid(input, "trailing characters"));
        }

        let days = days_from_civil(year, month, day);
        let seconds =
            days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second)
                - i64::from(offset_seconds);
        Ok(Self::from_unix_seconds(seconds))
    }

    pub fn parse_json(value: &Value, path: &str) -> Result<Self, AdmissionError> {
        match value {
            Value::String(text) => Self::parse(text),
            Value::Number(number) => {
                number.as_i64().map(Self::from_unix_seconds).ok_or_else(|| {
                    AdmissionError::at_path(
                        E_INVALID_TIMESTAMP,
                        path,
                        "Unix timestamp must be an integer",
                    )
                })
            }
            _ => Err(AdmissionError::at_path(
                E_INVALID_TIMESTAMP,
                path,
                "expected RFC3339 string or Unix seconds",
            )),
        }
    }
}

fn invalid(input: &str, reason: &str) -> AdmissionError {
    AdmissionError::new(
        E_INVALID_TIMESTAMP,
        format!("invalid timestamp {input:?}: {reason}"),
    )
}

fn number(part: &str, input: &str, name: &str) -> Result<i32, AdmissionError> {
    if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(input, &format!("invalid {name}")));
    }
    Ok(part.parse::<i32>().unwrap_or_default())
}

fn days_in_month(year: i32, month: i32) -> i32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_from_civil(year: i32, month: i32, day: i32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    i64::from(era) * 146_097 + i64::from(day_of_era) - 719_468
}
