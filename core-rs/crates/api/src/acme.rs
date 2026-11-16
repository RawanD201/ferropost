//! Certificates from Let's Encrypt over HTTP-01 (Go: `service/acme` with
//! lego).
//!
//! Challenges are answered by this server's own `/.well-known/acme-challenge/`
//! route (Go ran a second server on port 60880 behind a proxy). Unlike Go,
//! the new certificate and its key are not also left in the shared `ssl/`
//! directory as `certificate.pem` and `private_key.pem`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use axum::extract::{Path, Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};

use crate::state::AppState;

/// One order at a time: they share the account and Let's Encrypt's rate
/// limits.
static ONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn account_path(state: &AppState) -> PathBuf {
    state.config.root.join("data/acme/ferropost-account.json")
}

/// The stored ACME account, or a new one (credentials kept owner-only).
async fn account(state: &AppState, email: &str) -> Result<Account> {
    let path = account_path(state);
    if let Ok(raw) = tokio::fs::read(&path).await {
        let credentials: AccountCredentials =
            serde_json::from_slice(&raw).context("stored ACME account")?;
        return Account::builder()?
            .from_credentials(credentials)
            .await
            .context("restore ACME account");
    }
    let contact = format!("mailto:{email}");
    let contacts: Vec<&str> = if ferropost_domain::contacts::is_valid_email(email) {
        vec![contact.as_str()]
    } else {
        Vec::new()
    };
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            state.config.acme_directory.clone(),
            None,
        )
        .await
        .context("register ACME account")?;
    let json = serde_json::to_vec(&credentials)?;
    let dir = path.parent().map(PathBuf::from);
    tokio::task::spawn_blocking(move || -> Result<()> {
        if let Some(dir) = dir {
            std::fs::create_dir_all(dir)?;
        }
        crate::fsio::write_atomic(&path, &json, 0o600)?;
        Ok(())
    })
    .await
    .map_err(|e| anyhow!("save ACME account: {e}"))??;
    Ok(account)
}

/// A new RSA-2048 key (as Go's certificates used) and a CSR for `host`.
pub fn key_and_csr(host: &str) -> Result<(String, Vec<u8>)> {
    let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).context("generate key")?;
    let der = key.to_pkcs8_der().context("encode key")?;
    let pem = key.to_pkcs8_pem(LineEnding::LF).context("encode key")?;
    let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(der.as_bytes()),
        &rcgen::PKCS_RSA_SHA256,
    )
    .context("load key")?;
    let mut params = rcgen::CertificateParams::new(vec![host.to_owned()]).context("names")?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host);
    let csr = params.serialize_request(&pair).context("sign CSR")?;
    Ok((pem.to_string(), csr.der().to_vec()))
}

/// A certificate chain and its key, PEM.
pub struct Obtained {
    pub chain: String,
    pub key: String,
}

/// Why an order failed, from its challenges.
async fn failure(order: &mut instant_acme::Order) -> String {
    if let Some(problem) = &order.state().error {
        return problem.to_string();
    }
    let mut reasons = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(Ok(authz)) = authorizations.next().await {
        for challenge in &authz.challenges {
            if let Some(problem) = &challenge.error {
                reasons.push(problem.to_string());
            }
        }
    }
    if reasons.is_empty() {
        "the order was not validated".to_owned()
    } else {
        reasons.join("; ")
    }
}

/// Obtains a certificate for `host`, answering the HTTP-01 challenge on
/// port 80 of this server.
pub async fn obtain(state: &AppState, host: &str, email: &str) -> Result<Obtained> {
    let _one = ONE.lock().await;
    let account = account(state, email).await?;
    let identifiers = [Identifier::Dns(host.to_owned())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("create order")?;
    let mut tokens: Vec<String> = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.context("authorization")?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => bail!("authorization for {host} is {other:?}"),
            }
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| anyhow!("no HTTP-01 challenge offered for {host}"))?;
            let token = challenge.token.clone();
            state
                .caches
                .acme_challenges
                .insert(
                    token.clone(),
                    challenge.key_authorization().as_str().to_owned(),
                )
                .await;
            tokens.push(token);
            challenge.set_ready().await.context("challenge ready")?;
        }
    }
    let ready = order
        .poll_ready(
            &RetryPolicy::new()
                .initial_delay(Duration::from_secs(1))
                .backoff(1.5)
                .timeout(Duration::from_secs(120)),
        )
        .await;
    for token in &tokens {
        state.caches.acme_challenges.invalidate(token).await;
    }
    match ready.context("validation")? {
        OrderStatus::Ready => {}
        _ => bail!("{}", failure(&mut order).await),
    }
    let host_owned = host.to_owned();
    let (key, csr) = tokio::task::spawn_blocking(move || key_and_csr(&host_owned))
        .await
        .map_err(|e| anyhow!("key: {e}"))??;
    order.finalize_csr(&csr).await.context("finalize")?;
    let chain = order
        .poll_certificate(
            &RetryPolicy::new()
                .initial_delay(Duration::from_secs(1))
                .timeout(Duration::from_secs(120)),
        )
        .await
        .context("certificate")?;
    Ok(Obtained { chain, key })
}

/// `GET /.well-known/acme-challenge/<token>`: answers this server's
/// challenges; anything else goes to Go, whose own requests are answered
/// there until domains move.
pub async fn challenge(
    State(state): State<AppState>,
    Path(token): Path<String>,
    req: Request,
) -> Response {
    match state.caches.acme_challenges.get(&token).await {
        Some(key_authorization) => (
            [(CONTENT_TYPE, "application/octet-stream")],
            key_authorization,
        )
            .into_response(),
        None => crate::proxy::forward(State(state), req).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::FromDer;

    #[test]
    fn csr_names_the_host() {
        let (key, csr) = key_and_csr("mail.example.test").expect("csr");
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
        let (_, parsed) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&csr)
                .expect("parse");
        let names: Vec<String> = parsed
            .requested_extensions()
            .into_iter()
            .flatten()
            .filter_map(|ext| match ext {
                x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => Some(
                    san.general_names
                        .iter()
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(names, ["DNSName(mail.example.test)"]);
        // The CSR carries the key's public half.
        use rsa::pkcs1::EncodeRsaPublicKey;
        use rsa::pkcs8::DecodePrivateKey;
        let public = rsa::RsaPrivateKey::from_pkcs8_pem(&key)
            .expect("key")
            .to_public_key()
            .to_pkcs1_der()
            .expect("public");
        assert_eq!(
            parsed
                .certification_request_info
                .subject_pki
                .subject_public_key
                .data
                .as_ref(),
            public.as_bytes()
        );
    }
}
