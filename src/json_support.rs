use crate::error::{AdmissionError, Result, E_INVALID_FIELD};
use serde_json::{Map, Value};

pub(crate) fn object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| AdmissionError::at_path(E_INVALID_FIELD, path, "expected a JSON object"))
}

pub(crate) fn find<'a, 'b>(
    map: &'a Map<String, Value>,
    names: &'b [&'b str],
) -> Option<(&'b str, &'a Value)> {
    for name in names {
        if let Some(value) = map.get(*name) {
            return Some((name, value));
        }
    }
    None
}

pub(crate) fn required_string(
    map: &Map<String, Value>,
    names: &[&str],
    path: &str,
) -> Result<String> {
    match find(map, names) {
        Some((_name, Value::String(value))) => Ok(value.clone()),
        Some((name, _)) => Err(AdmissionError::at_path(
            E_INVALID_FIELD,
            format!("{path}.{name}"),
            "expected a string",
        )),
        None => Err(AdmissionError::at_path(
            E_INVALID_FIELD,
            format!("{path}.{}", names[0]),
            "required field is missing",
        )),
    }
}

pub(crate) fn optional_string(
    map: &Map<String, Value>,
    names: &[&str],
    path: &str,
) -> Result<Option<String>> {
    match find(map, names) {
        Some((_, Value::Null)) | None => Ok(None),
        Some((_, Value::String(value))) => Ok(Some(value.clone())),
        Some((name, _)) => Err(AdmissionError::at_path(
            E_INVALID_FIELD,
            format!("{path}.{name}"),
            "expected a string",
        )),
    }
}

pub(crate) fn optional_bool(
    map: &Map<String, Value>,
    names: &[&str],
    path: &str,
) -> Result<Option<bool>> {
    match find(map, names) {
        Some((_, Value::Null)) | None => Ok(None),
        Some((_, Value::Bool(value))) => Ok(Some(*value)),
        Some((name, _)) => Err(AdmissionError::at_path(
            E_INVALID_FIELD,
            format!("{path}.{name}"),
            "expected a boolean",
        )),
    }
}

pub(crate) fn optional_i64(
    map: &Map<String, Value>,
    names: &[&str],
    path: &str,
) -> Result<Option<i64>> {
    match find(map, names) {
        Some((_, Value::Null)) | None => Ok(None),
        Some((_, Value::Number(number))) => number.as_i64().map(Some).ok_or_else(|| {
            AdmissionError::at_path(
                E_INVALID_FIELD,
                format!("{path}.{}", names[0]),
                "expected an integer",
            )
        }),
        Some((name, _)) => Err(AdmissionError::at_path(
            E_INVALID_FIELD,
            format!("{path}.{name}"),
            "expected an integer",
        )),
    }
}

pub(crate) fn string_list(
    map: &Map<String, Value>,
    names: &[&str],
    path: &str,
) -> Result<Vec<String>> {
    match find(map, names) {
        Some((_, Value::Null)) | None => Ok(Vec::new()),
        Some((_, Value::String(value))) => Ok(vec![value.clone()]),
        Some((name, Value::Array(values))) => values
            .iter()
            .enumerate()
            .map(|(index, value)| match value {
                Value::String(value) => Ok(value.clone()),
                _ => Err(AdmissionError::at_path(
                    E_INVALID_FIELD,
                    format!("{path}.{name}[{index}]"),
                    "expected a string",
                )),
            })
            .collect(),
        Some((name, _)) => Err(AdmissionError::at_path(
            E_INVALID_FIELD,
            format!("{path}.{name}"),
            "expected a string or array of strings",
        )),
    }
}
