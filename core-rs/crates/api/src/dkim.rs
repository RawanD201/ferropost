//! The DKIM keys rspamd signs with and its signing configuration (Go:
//! `getDKIMRecordWithKeySize`, `RepairDKIMSigningConfig`,
//! `FixRspamdDKIMSigningConfig`).
//!
//! Differences from Go:
//! - Keys are made here, when a domain is created or found without them
//!   (Go ran `rspamadm dkim_keygen` in the rspamd container from whatever
//!   asked for the record, the domain list included, and restarted rspamd
//!   once per key).
//! - An existing private key is never replaced: a missing public half is
//!   derived from it (Go made a new pair, so the published record stopped
//!   matching).
//! - Private keys belong to rspamd's user and are readable by it only (Go:
//!   0644, readable by every account on the host).
//! - The signing configuration is rewritten and rspamd restarted only when
//!   something changed (Go restarted rspamd at every start of the core).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use ferropost_domain::domains::{DKIM_SELECTORS, dkim_pub_file, dkim_value, dkim_value_from_pub};
use ferropost_domain::relay as relay_rules;
use ferropost_domain::settings::is_valid_hostname;
use ferropost_store::relay as relay_store;
use rsa::RsaPrivateKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};

use crate::postfix::write_if_changed;
use crate::state::AppState;

static KEYS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static SIGNING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn key_dir(state: &AppState, domain: &str) -> PathBuf {
    state.config.rspamd_data_dir.join("dkim").join(domain)
}

/// rspamd's user: the owner of its data directory, which its container
/// hands to `_rspamd` at every start.
fn rspamd_owner(state: &AppState) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(&state.config.rspamd_data_dir)
        .ok()
        .map(|m| (m.uid(), m.gid()))
}

fn public_b64(key: &RsaPrivateKey) -> Result<String> {
    let der = key
        .to_public_key()
        .to_public_key_der()
        .context("encode DKIM public key")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(der.as_bytes()))
}

fn load(pem: &str) -> Option<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs1_pem(pem)
        .ok()
        .or_else(|| RsaPrivateKey::from_pkcs8_pem(pem).ok())
}

/// Hands a new file to rspamd's user; where that is not possible (not
/// root), leaves it readable as Go did, so signing keeps working.
fn give_to_rspamd(path: &Path, owner: Option<(u32, u32)>) {
    use std::os::unix::fs::PermissionsExt;
    let Some((uid, gid)) = owner else {
        return;
    };
    if let Err(err) = std::os::unix::fs::chown(path, Some(uid), Some(gid)) {
        use std::os::unix::fs::MetadataExt;
        let owned = std::fs::metadata(path).is_ok_and(|m| m.uid() == uid);
        if !owned {
            tracing::warn!(path = %path.display(), %err, "DKIM key left readable: cannot hand it to rspamd");
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
        }
    }
}

/// Makes one selector's key when its private half is missing. Returns
/// whether a new key was made.
fn ensure_key(dir: &Path, selector: &str, bits: usize, owner: Option<(u32, u32)>) -> Result<bool> {
    let private = dir.join(format!("{selector}.private"));
    let public = dir.join(format!("{selector}.pub"));
    match std::fs::read_to_string(&private) {
        Ok(pem) => {
            if !public.exists() {
                match load(&pem) {
                    Some(key) => {
                        let file = dkim_pub_file(selector, &public_b64(&key)?);
                        crate::fsio::write_atomic(&public, file.as_bytes(), 0o644)?;
                    }
                    None => {
                        tracing::warn!(path = %private.display(), "DKIM key not readable; left alone")
                    }
                }
            }
            return Ok(false);
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("read {}", private.display()));
        }
    }
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    give_to_rspamd(dir, owner);
    let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, bits).context("generate DKIM key")?;
    let pem = key
        .to_pkcs1_pem(LineEnding::LF)
        .context("encode DKIM key")?;
    crate::fsio::write_atomic(&private, pem.as_bytes(), 0o600)?;
    give_to_rspamd(&private, owner);
    let file = dkim_pub_file(selector, &public_b64(&key)?);
    crate::fsio::write_atomic(&public, file.as_bytes(), 0o644)?;
    Ok(true)
}

/// Makes the domain's missing keys. Returns whether any was made.
pub async fn ensure_keys(state: &AppState, domain: &str) -> Result<bool> {
    if !is_valid_hostname(domain) {
        return Err(anyhow!("not a domain name: {domain:?}"));
    }
    let dir = key_dir(state, domain);
    let owner = rspamd_owner(state);
    let _keys = KEYS.lock().await;
    tokio::task::spawn_blocking(move || -> Result<bool> {
        let mut made = false;
        for (selector, bits) in DKIM_SELECTORS {
            made |= ensure_key(&dir, selector, bits, owner)?;
        }
        Ok(made)
    })
    .await
    .map_err(|e| anyhow!("DKIM keys: {e}"))?
}

/// The TXT value of a domain's key: its `.pub` file, else derived from the
/// private key. `None` when there is no key.
pub async fn record(state: &AppState, domain: &str, selector: &str) -> Option<String> {
    if !is_valid_hostname(domain) {
        return None;
    }
    let dir = key_dir(state, domain);
    if let Ok(content) = tokio::fs::read_to_string(dir.join(format!("{selector}.pub"))).await
        && let Some(value) = dkim_value_from_pub(&content)
    {
        return Some(value);
    }
    let pem = tokio::fs::read_to_string(dir.join(format!("{selector}.private")))
        .await
        .ok()?;
    tokio::task::spawn_blocking(move || {
        load(&pem)
            .and_then(|key| public_b64(&key).ok())
            .map(|b64| dkim_value(&b64))
    })
    .await
    .ok()
    .flatten()
}

/// Makes existing private keys readable by rspamd only, where they already
/// belong to it (Go left them readable by everyone).
pub async fn tighten_keys(state: &AppState) -> Result<usize> {
    let root = state.config.rspamd_data_dir.join("dkim");
    let Some((uid, _)) = rspamd_owner(state) else {
        return Ok(0);
    };
    tokio::task::spawn_blocking(move || -> Result<usize> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mut tightened = 0;
        let Ok(domains) = std::fs::read_dir(&root) else {
            return Ok(0);
        };
        for dir in domains.flatten() {
            let Ok(files) = std::fs::read_dir(dir.path()) else {
                continue;
            };
            for file in files.flatten() {
                let path = file.path();
                if path.extension().is_none_or(|e| e != "private") {
                    continue;
                }
                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.file_type().is_file() && meta.uid() == uid && meta.mode() & 0o077 != 0 {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                    tightened += 1;
                }
            }
        }
        Ok(tightened)
    })
    .await
    .map_err(|e| anyhow!("tighten DKIM keys: {e}"))?
}

/// Makes missing keys and writes rspamd's `dkim_signing.conf` for every
/// domain except those sent through an active relay, whose provider signs
/// them. Restarts rspamd when the file or a key changed. Returns whether
/// it did.
pub async fn sync_signing(state: &AppState) -> Result<bool> {
    let _one = SIGNING.lock().await;
    let pg = &state.store.pg;
    let all: Vec<String> = relay_store::all_domains(pg)
        .await?
        .into_iter()
        .filter(|d| is_valid_hostname(d))
        .collect();
    let mut made = false;
    for domain in &all {
        match ensure_keys(state, domain).await {
            Ok(m) => made |= m,
            Err(err) => tracing::warn!(%domain, error = %format!("{err:#}"), "DKIM key not made"),
        }
    }
    let relayed = relay_store::relayed_domains(pg).await?;
    let domains: Vec<String> = all
        .into_iter()
        .filter(|d| !relayed.contains(&d.to_ascii_lowercase()))
        .collect();
    let mut changed = false;
    let dir = state.config.rspamd_local_d.clone();
    if dir.is_dir() {
        let path = dir.join("dkim_signing.conf");
        // The same domains in another order is no change (Go wrote the
        // file in its own order; rewriting would restart rspamd for
        // nothing).
        let mut wanted = domains.clone();
        wanted.sort();
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        let same = current.starts_with("sign_headers")
            && current.contains("\nuse_esld = false;")
            && relay_rules::dkim_signed_domains(&current) == wanted;
        if !same {
            let content = relay_rules::dkim_signing_conf(&domains);
            changed = tokio::task::spawn_blocking(move || write_if_changed(&path, &content, None))
                .await
                .map_err(|e| anyhow!("write DKIM signing config: {e}"))??;
        }
    } else {
        tracing::debug!(path = %dir.display(), "rspamd local.d missing; DKIM signing not written");
    }
    if changed || made {
        crate::docker::restart_named(&state.config, &state.config.rspamd_container).await?;
    }
    Ok(changed || made)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_made_once_and_kept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let domain = dir.path().join("ex.test");
        assert!(ensure_key(&domain, "short", 1024, None).expect("make"));
        let private = std::fs::read_to_string(domain.join("short.private")).expect("private");
        assert!(private.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        let value =
            dkim_value_from_pub(&std::fs::read_to_string(domain.join("short.pub")).expect("pub"))
                .expect("value");
        assert!(value.starts_with("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"));
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(domain.join("short.private"))
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // A lost public half comes back from the key; the key stays.
        std::fs::remove_file(domain.join("short.pub")).expect("remove");
        assert!(!ensure_key(&domain, "short", 1024, None).expect("again"));
        assert_eq!(
            std::fs::read_to_string(domain.join("short.private")).expect("private"),
            private
        );
        let again =
            dkim_value_from_pub(&std::fs::read_to_string(domain.join("short.pub")).expect("pub"))
                .expect("value");
        assert_eq!(again, value);
    }
}
