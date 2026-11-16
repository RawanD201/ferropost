//! A FastCGI client (one request per connection), for PHP-FPM serving
//! Roundcube (Go used `fcgi_client`).

use std::io;

use axum::http::{HeaderName, HeaderValue, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const BEGIN_REQUEST: u8 = 1;
pub const END_REQUEST: u8 = 3;
pub const PARAMS: u8 = 4;
pub const STDIN: u8 = 5;
pub const STDOUT: u8 = 6;
pub const STDERR: u8 = 7;
const VERSION: u8 = 1;
const REQUEST_ID: u16 = 1;
const RESPONDER: u16 = 1;
/// Largest record content.
pub const MAX_CONTENT: usize = 65_535;

/// One record, padded to eight bytes.
pub fn record(kind: u8, content: &[u8]) -> Vec<u8> {
    debug_assert!(content.len() <= MAX_CONTENT);
    let padding = (8 - content.len() % 8) % 8;
    let mut out = Vec::with_capacity(8 + content.len() + padding);
    out.extend_from_slice(&[VERSION, kind]);
    out.extend_from_slice(&REQUEST_ID.to_be_bytes());
    out.extend_from_slice(
        &u16::try_from(content.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    out.push(u8::try_from(padding).unwrap_or(0));
    out.push(0);
    out.extend_from_slice(content);
    out.resize(out.len() + padding, 0);
    out
}

/// `BEGIN_REQUEST` for a responder that closes the connection after.
pub fn begin_request() -> Vec<u8> {
    let mut body = RESPONDER.to_be_bytes().to_vec();
    body.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    record(BEGIN_REQUEST, &body)
}

fn length(n: usize, out: &mut Vec<u8>) {
    if n < 128 {
        out.push(u8::try_from(n).unwrap_or(0));
    } else {
        let n = u32::try_from(n).unwrap_or(u32::MAX) | 0x8000_0000;
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// The parameters as `PARAMS` records, ending with the empty one.
pub fn params(pairs: &[(String, String)]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for (name, value) in pairs {
        length(name.len(), &mut encoded);
        length(value.len(), &mut encoded);
        encoded.extend_from_slice(name.as_bytes());
        encoded.extend_from_slice(value.as_bytes());
    }
    let mut out = Vec::new();
    for chunk in encoded.chunks(MAX_CONTENT) {
        out.extend(record(PARAMS, chunk));
    }
    out.extend(record(PARAMS, &[]));
    out
}

/// Request body bytes as `STDIN` records (without the closing one).
pub fn stdin(chunk: &[u8]) -> Vec<u8> {
    chunk
        .chunks(MAX_CONTENT)
        .flat_map(|part| record(STDIN, part))
        .collect()
}

/// A record read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub kind: u8,
    pub content: Vec<u8>,
}

/// The next record; `None` at the end of the stream.
pub async fn read_record<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Record>> {
    let mut header = [0u8; 8];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let padding = usize::from(header[6]);
    let mut content = vec![0u8; length + padding];
    reader.read_exact(&mut content).await?;
    content.truncate(length);
    Ok(Some(Record {
        kind: header[1],
        content,
    }))
}

/// The CGI headers at the start of a script's output.
#[derive(Debug, Clone)]
pub struct CgiHead {
    pub status: StatusCode,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// Where the body starts.
    pub body_start: usize,
}

/// The CGI headers at the start of a script's output; `None` until the
/// blank line arrived.
pub fn split_headers(output: &[u8]) -> Option<CgiHead> {
    let (head_end, body_start) = output
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, i + 4))
        .or_else(|| {
            output
                .windows(2)
                .position(|w| w == b"\n\n")
                .map(|i| (i, i + 2))
        })?;
    let head = String::from_utf8_lossy(&output[..head_end]);
    let mut status = None;
    let mut headers = Vec::new();
    for line in head.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.trim().eq_ignore_ascii_case("status") {
            status = value
                .split_whitespace()
                .next()
                .and_then(|code| code.parse::<u16>().ok())
                .and_then(|code| StatusCode::from_u16(code).ok());
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.trim().as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.push((name, value));
        }
    }
    let status = status.unwrap_or_else(|| {
        if headers
            .iter()
            .any(|(n, _)| n == axum::http::header::LOCATION)
        {
            StatusCode::FOUND
        } else {
            StatusCode::OK
        }
    });
    Some(CgiHead {
        status,
        headers,
        body_start,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_round_trip() {
        let mut wire = begin_request();
        wire.extend(params(&[
            (
                "SCRIPT_FILENAME".to_owned(),
                "/var/www/html/index.php".to_owned(),
            ),
            ("LONG".to_owned(), "x".repeat(300)),
        ]));
        wire.extend(stdin(b"a=1"));
        wire.extend(record(STDIN, &[]));
        assert_eq!(wire.len() % 8, 0);
        let mut reader = wire.as_slice();
        let begin = read_record(&mut reader)
            .await
            .expect("read")
            .expect("record");
        assert_eq!(
            (begin.kind, begin.content[..2].to_vec()),
            (BEGIN_REQUEST, vec![0, 1])
        );
        let params = read_record(&mut reader)
            .await
            .expect("read")
            .expect("record");
        assert_eq!(params.kind, PARAMS);
        assert_eq!(
            &params.content[..2],
            &[15, 23],
            "short lengths take one byte"
        );
        assert_eq!(&params.content[40..42], &[4, 0x80], "long ones four bytes");
        let end_params = read_record(&mut reader)
            .await
            .expect("read")
            .expect("record");
        assert_eq!((end_params.kind, end_params.content.len()), (PARAMS, 0));
        let body = read_record(&mut reader)
            .await
            .expect("read")
            .expect("record");
        assert_eq!((body.kind, body.content), (STDIN, b"a=1".to_vec()));
        let end = read_record(&mut reader)
            .await
            .expect("read")
            .expect("record");
        assert_eq!((end.kind, end.content.len()), (STDIN, 0));
        assert_eq!(read_record(&mut reader).await.expect("read"), None);
    }

    #[test]
    fn cgi_headers() {
        let output: &[u8] =
            b"Status: 302 Found\r\nLocation: /x\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nbody";
        let head = split_headers(output).expect("headers");
        assert_eq!(head.status, StatusCode::FOUND);
        assert_eq!(head.headers.len(), 3, "both cookies kept");
        assert_eq!(&output[head.body_start..], b"body");
        let head = split_headers(b"Content-Type: text/html\n\nhi").expect("headers");
        assert_eq!(head.status, StatusCode::OK);
        let head = split_headers(b"Location: /login\r\n\r\n").expect("headers");
        assert_eq!(head.status, StatusCode::FOUND);
        assert!(
            split_headers(b"Content-Type: text/html\r\n").is_none(),
            "not complete yet"
        );
    }
}
