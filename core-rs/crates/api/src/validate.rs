//! Input checks with GoFrame's English messages, so the console shows the
//! same validation errors as before. Failures are code 412.

use crate::envelope::ApiError;

fn fail(msg: String) -> ApiError {
    ApiError::Validation(msg)
}

/// `required`: a non-blank string, returned trimmed.
pub fn required<'a>(field: &str, value: &'a Option<String>) -> Result<&'a str, ApiError> {
    match value.as_deref().map(str::trim) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(fail(format!("The {field} field is required"))),
    }
}

/// `max-length`, counted in characters like GoFrame.
pub fn max_len(field: &str, value: &str, max: usize) -> Result<(), ApiError> {
    if value.chars().count() > max {
        return Err(fail(format!(
            "The {field} value `{value}` length must be equal or lesser than {max}"
        )));
    }
    Ok(())
}

/// `required|min:1` for a row ID.
pub fn id(field: &str, value: Option<i64>) -> Result<i32, ApiError> {
    let value = value.ok_or_else(|| fail(format!("The {field} field is required")))?;
    if value < 1 {
        return Err(fail(format!(
            "The {field} value `{value}` must be equal or greater than 1"
        )));
    }
    i32::try_from(value).map_err(|_| fail(format!("The {field} value `{value}` is out of range")))
}

/// Optional row ID: absent or `0` means "none".
pub fn optional_id(field: &str, value: Option<i64>) -> Result<Option<i32>, ApiError> {
    match value {
        None | Some(0) => Ok(None),
        Some(v) => id(field, Some(v)).map(Some),
    }
}

/// `required|in:a,b,...`
pub fn one_of(field: &str, value: Option<i64>, allowed: &[i64]) -> Result<i64, ApiError> {
    let value = value.ok_or_else(|| fail(format!("The {field} field is required")))?;
    if !allowed.contains(&value) {
        let list = allowed
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        return Err(fail(format!(
            "The {field} value `{value}` is not in acceptable range: {list}"
        )));
    }
    Ok(value)
}

/// `in:a,b,...` for an optional value; absent means `default`.
pub fn optional_one_of(
    field: &str,
    value: Option<i64>,
    allowed: &[i64],
    default: i64,
) -> Result<i64, ApiError> {
    match value {
        None => Ok(default),
        Some(v) => one_of(field, Some(v), allowed),
    }
}

/// `required|in:A,B,...` for a string.
pub fn str_one_of<'a>(
    field: &str,
    value: &'a Option<String>,
    allowed: &[&str],
) -> Result<&'a str, ApiError> {
    let value = required(field, value)?;
    if !allowed.contains(&value) {
        return Err(fail(format!(
            "The {field} value `{value}` is not in acceptable range: {}",
            allowed.join(",")
        )));
    }
    Ok(value)
}

/// `in:A,B,...` for an optional string; empty counts as absent.
pub fn optional_str_in(
    field: &str,
    value: &Option<String>,
    allowed: &[&str],
) -> Result<(), ApiError> {
    match value.as_deref().map(str::trim) {
        None | Some("") => Ok(()),
        Some(_) => str_one_of(field, value, allowed).map(|_| ()),
    }
}

/// `required|min-length:1` for a list of row IDs. Duplicates are removed.
pub fn id_list(field: &str, values: &[i64]) -> Result<Vec<i32>, ApiError> {
    if values.is_empty() {
        return Err(fail(format!("The {field} field is required")));
    }
    let mut ids = Vec::with_capacity(values.len());
    for value in values {
        let id = id(field, Some(*value))?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(err: ApiError) -> String {
        match err {
            ApiError::Validation(m) => m,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn messages_match_goframe() {
        assert_eq!(
            msg(required("name", &None).expect_err("must fail")),
            "The name field is required"
        );
        assert_eq!(
            msg(required("name", &Some("  ".into())).expect_err("must fail")),
            "The name field is required"
        );
        assert_eq!(required("name", &Some(" vip ".into())).expect("ok"), "vip");
        assert_eq!(
            msg(max_len("name", "abcd", 3).expect_err("must fail")),
            "The name value `abcd` length must be equal or lesser than 3"
        );
        assert!(max_len("name", "日本語", 3).is_ok());
        assert_eq!(
            msg(id("id", Some(0)).expect_err("must fail")),
            "The id value `0` must be equal or greater than 1"
        );
        assert_eq!(
            msg(one_of("mark_include", Some(2), &[0, 1]).expect_err("must fail")),
            "The mark_include value `2` is not in acceptable range: 0,1"
        );
    }

    #[test]
    fn enums() {
        assert_eq!(optional_one_of("x", None, &[0, 1], 0).expect("ok"), 0);
        assert!(optional_one_of("x", Some(3), &[0, 1], 0).is_err());
        assert_eq!(
            str_one_of("tag_logic", &Some("OR".into()), &["AND", "OR", "NOT"]).expect("ok"),
            "OR"
        );
        assert_eq!(
            msg(str_one_of("tag_logic", &Some("XOR".into()), &["AND", "OR"])
                .expect_err("must fail")),
            "The tag_logic value `XOR` is not in acceptable range: AND,OR"
        );
        assert!(optional_str_in("file_type", &Some(String::new()), &["csv"]).is_ok());
        assert!(optional_str_in("file_type", &Some("pdf".into()), &["csv"]).is_err());
    }

    #[test]
    fn ids() {
        assert_eq!(id("id", Some(5)).expect("ok"), 5);
        assert!(id("id", None).is_err());
        assert!(id("id", Some(i64::MAX)).is_err());
        assert_eq!(optional_id("g", Some(0)).expect("ok"), None);
        assert_eq!(id_list("tag_ids", &[3, 1, 3]).expect("ok"), vec![3, 1]);
        assert!(id_list("tag_ids", &[]).is_err());
        assert!(id_list("tag_ids", &[1, -1]).is_err());
    }
}
