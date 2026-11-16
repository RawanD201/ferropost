//! Images AskAI keeps for brands (logos and other uploads), stored on this
//! server in `data/media/` and served at `/media/<id>.<ext>` to the console
//! and to mail clients. Go uploaded them to BillionMail's own service
//! (`cdn.billionmail.com`).

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use ferropost_domain::askai::is_item_id;

use crate::state::AppState;

/// Largest image accepted.
pub const MAX_IMAGE_BYTES: usize = 5 * 1024 * 1024;

fn dir(state: &AppState) -> PathBuf {
    state.config.root.join("data/media")
}

/// The image formats mail clients show, by their first bytes (SVG is
/// refused: it can carry scripts and most mail clients drop it).
pub fn kind_of(bytes: &[u8]) -> Option<(&'static str, &'static str)> {
    match bytes {
        [0x89, b'P', b'N', b'G', ..] => Some(("png", "image/png")),
        [0xff, 0xd8, 0xff, ..] => Some(("jpg", "image/jpeg")),
        [b'G', b'I', b'F', b'8', b'7' | b'9', b'a', ..] => Some(("gif", "image/gif")),
        [
            b'R',
            b'I',
            b'F',
            b'F',
            _,
            _,
            _,
            _,
            b'W',
            b'E',
            b'B',
            b'P',
            ..,
        ] => Some(("webp", "image/webp")),
        [0, 0, 1, 0, ..] => Some(("ico", "image/x-icon")),
        _ => None,
    }
}

fn mime_of(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "png" => "image/png",
        "jpg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        _ => return None,
    })
}

/// The bytes of a `data:` URL (what the console sends) or of plain base64.
pub fn decode(data: &str) -> Result<Vec<u8>> {
    let data = data.trim();
    let payload = match data.strip_prefix("data:") {
        Some(rest) => {
            let (meta, payload) = rest.split_once(',').context("not a data URL")?;
            if !meta.ends_with(";base64") {
                bail!("the image must be base64-encoded");
            }
            payload
        }
        None => data,
    };
    if payload.len() > MAX_IMAGE_BYTES * 4 / 3 + 4 {
        bail!("the image is larger than 5 MB");
    }
    let clean: String = payload.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(clean)
        .context("the image is not valid base64")
}

/// A stored image.
pub struct Stored {
    pub id: String,
    pub url: String,
}

/// Stores an image and returns its public address.
pub async fn store(state: &AppState, bytes: &[u8]) -> Result<Stored> {
    if bytes.len() > MAX_IMAGE_BYTES {
        bail!("the image is larger than 5 MB");
    }
    let (ext, _) =
        kind_of(bytes).context("only PNG, JPEG, GIF, WebP and ICO images are accepted")?;
    let id = uuid::Uuid::now_v7().to_string();
    let path = dir(state).join(format!("{id}.{ext}"));
    let content = bytes.to_vec();
    tokio::task::spawn_blocking(move || -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::fsio::write_atomic(&path, &content, 0o644)?;
        Ok(())
    })
    .await
    .context("store image")??;
    let base = crate::base_url::global(state).await;
    Ok(Stored {
        url: format!("{base}/media/{id}.{ext}"),
        id,
    })
}

/// `<id>.<ext>` of an image stored here.
fn parse_name(name: &str) -> Option<(&str, &'static str)> {
    let (id, ext) = name.rsplit_once('.')?;
    let mime = mime_of(ext)?;
    is_item_id(id).then_some((id, mime))
}

/// Deletes the stored image an address points to, if it is one of ours.
pub async fn remove_url(state: &AppState, url: &str) {
    let Some(name) = url.rsplit_once("/media/").map(|(_, name)| name) else {
        return;
    };
    if parse_name(name).is_some() {
        let _ = tokio::fs::remove_file(dir(state).join(name)).await;
    }
}

/// `GET /media/{file}` (public: mail clients load these).
pub async fn serve(State(state): State<AppState>, Path(file): Path<String>) -> Response {
    let Some((_, mime)) = parse_name(&file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match tokio::fs::read(dir(&state).join(&file)).await {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, mime),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                (header::CONTENT_SECURITY_POLICY, "default-src 'none'"),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn images() {
        assert_eq!(kind_of(b"\x89PNG\r\n\x1a\n...").map(|k| k.0), Some("png"));
        assert_eq!(kind_of(b"GIF89a....").map(|k| k.0), Some("gif"));
        assert_eq!(kind_of(b"RIFF\0\0\0\0WEBPVP8 ").map(|k| k.0), Some("webp"));
        assert_eq!(kind_of(b"<svg onload=alert(1)>"), None);
        let png = decode("data:image/png;base64,iVBORw0KGgo=").expect("png");
        assert_eq!(&png[..4], b"\x89PNG");
        assert!(decode("data:image/png,raw").is_err());
        assert_eq!(
            parse_name("0190f2c4-7d9c-7c3e-9a3f-1c2d3e4f5a6b.png").map(|n| n.1),
            Some("image/png")
        );
        assert_eq!(parse_name("../x.png"), None);
        assert_eq!(parse_name("x.svg"), None);
    }
}
