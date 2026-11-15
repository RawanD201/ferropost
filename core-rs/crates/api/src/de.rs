//! Lenient request decoding.
//!
//! GoFrame converted request values loosely, so the frontend sends things like
//! `group_id=` (empty) for "no filter". These helpers accept that while still
//! rejecting garbage.

use axum::extract::{FromRequestParts, Query};
use axum::http::request::Parts;
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer};

use crate::envelope::ApiError;

/// Query-string extractor whose failures become a 412 envelope instead of a
/// plain-text 400.
pub struct ApiQuery<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for ApiQuery<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        Query::<T>::try_from_uri(&parts.uri)
            .map(|Query(value)| Self(value))
            .map_err(|e| ApiError::Validation(e.body_text()))
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum IntOrString {
    Int(i64),
    Str(String),
}

/// Optional integer given as a number or a string; empty means absent.
pub fn opt_i64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<i64>, D::Error> {
    match Option::<IntOrString>::deserialize(deserializer)? {
        None => Ok(None),
        Some(IntOrString::Int(value)) => Ok(Some(value)),
        Some(IntOrString::Str(raw)) => {
            let raw = raw.trim();
            if raw.is_empty() {
                Ok(None)
            } else {
                raw.parse()
                    .map(Some)
                    .map_err(|_| D::Error::custom(format!("invalid integer `{raw}`")))
            }
        }
    }
}

/// List of integers given as a JSON array (numbers or numeric strings) or a
/// comma-separated string. Absent or empty means an empty list.
pub fn i64_list<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<i64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        List(Vec<IntOrString>),
        Text(String),
    }
    let parse = |raw: &str| {
        raw.trim()
            .parse::<i64>()
            .map_err(|_| D::Error::custom(format!("invalid integer `{}`", raw.trim())))
    };
    match Option::<Raw>::deserialize(deserializer)? {
        None => Ok(Vec::new()),
        Some(Raw::Text(text)) => text
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(parse)
            .collect(),
        Some(Raw::List(items)) => items
            .into_iter()
            .map(|item| match item {
                IntOrString::Int(v) => Ok(v),
                IntOrString::Str(s) => parse(&s),
            })
            .collect(),
    }
}

/// Optional string where empty means absent.
pub fn opt_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.filter(|s| !s.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Uri;

    #[derive(Debug, Deserialize)]
    struct Q {
        #[serde(default, deserialize_with = "opt_i64")]
        n: Option<i64>,
        #[serde(default, deserialize_with = "opt_string")]
        s: Option<String>,
    }

    fn parse(uri: &str) -> Result<Q, String> {
        let uri: Uri = uri.parse().expect("uri");
        Query::<Q>::try_from_uri(&uri)
            .map(|Query(q)| q)
            .map_err(|e| e.body_text())
    }

    #[derive(Debug, Deserialize)]
    struct L {
        #[serde(default, deserialize_with = "i64_list")]
        ids: Vec<i64>,
    }

    #[test]
    fn lenient_lists() {
        let parse = |json: &str| serde_json::from_str::<L>(json).map(|l| l.ids);
        assert_eq!(parse(r#"{"ids":[1,"2"]}"#).expect("ok"), vec![1, 2]);
        assert_eq!(parse(r#"{"ids":"3, 4"}"#).expect("ok"), vec![3, 4]);
        assert_eq!(parse(r#"{}"#).expect("ok"), Vec::<i64>::new());
        assert!(parse(r#"{"ids":["x"]}"#).is_err());
    }

    #[test]
    fn lenient_values() {
        let q = parse("/x?n=5&s=hi").expect("ok");
        assert_eq!((q.n, q.s.as_deref()), (Some(5), Some("hi")));
        let q = parse("/x?n=&s=").expect("ok");
        assert_eq!((q.n, q.s), (None, None));
        let q = parse("/x").expect("ok");
        assert_eq!((q.n, q.s), (None, None));
        assert!(parse("/x?n=abc").is_err());
    }
}
