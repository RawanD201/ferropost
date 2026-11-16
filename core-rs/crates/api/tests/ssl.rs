//! Mail host certificates: installing one for Postfix's and Dovecot's SNI,
//! keys never sent back, the DNS check and failure backoff before Let's
//! Encrypt is asked, the HTTP-01 challenge route (with Go's own challenges
//! still answered by Go), renewals, and the Dovecot SNI tidy.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use common::*;
use serde_json::json;

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn cert(host: &str) -> (String, String) {
    let mut params = rcgen::CertificateParams::new(vec![host.to_owned()]).expect("params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host);
    let key = rcgen::KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("cert");
    (cert.pem(), key.serialize_pem())
}

#[tokio::test]
async fn ssl() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    let ssl_dir = h.root.path().join("ssl");
    let postfix = h.root.path().join("conf/postfix");
    let conf_d = h.root.path().join("conf/dovecot/conf.d");
    std::fs::create_dir_all(&postfix).expect("postfix");
    std::fs::create_dir_all(&conf_d).expect("dovecot");
    let dovecot = conf_d.join("10-ssl.conf");
    std::fs::write(
        &dovecot,
        "ssl = required\n#DOMAIN_SSL_BEGIN_old.test\nlocal_name old.test {\n}\n#DOMAIN_SSL_END_old.test\nssl_cert = </etc/ssl/mail/cert.pem\n",
    )
    .expect("10-ssl.conf");
    for (domain, at) in [("example.test", 1), ("other.test", 2)] {
        sqlx::query("INSERT INTO domain (domain, create_time, active) VALUES ($1, $2, 1)")
            .bind(domain)
            .bind(at)
            .execute(pg)
            .await
            .expect("domain");
    }
    let ssl = ssl_dir.display().to_string();
    let env = [
        ("FERROPOST_SSL_DIR", ssl.as_str()),
        ("ADMIN_USERNAME", "admin"),
    ];
    let state = h.state(&env);
    let app = ferropost_api::app(state.clone());
    let admin = bearer(&token(1, "access_token", "admin-ssl"));
    let auth = admin.as_str();

    // --- Dovecot's SNI blocks go last (Go's FixDovecotSSLConfig) -------------------
    assert!(
        ferropost_api::mail_tls::fix_dovecot(&state)
            .await
            .expect("tidy")
    );
    assert!(read(&dovecot).ends_with("#DOMAIN_SSL_END_old.test\n"));
    assert!(
        !ferropost_api::mail_tls::fix_dovecot(&state)
            .await
            .expect("again")
    );

    // --- Installing a certificate ----------------------------------------------------
    let (chain, key) = cert("mail.example.test");
    let (_, other_key) = cert("mail.example.test");
    let set = |body: serde_json::Value| {
        let app = app.clone();
        async move { post(&app, "/api/domains/set_ssl", auth, body).await.body }
    };
    let r = set(json!({"domain": "example.test", "certificate": chain, "key": other_key})).await;
    assert_eq!(r["code"], 412, "a key must belong to its certificate: {r}");
    let r = set(json!({"domain": "nope.test", "certificate": chain, "key": key})).await;
    assert_eq!(r["msg"], "domain nope.test does not exist");
    let r = set(json!({"domain": "example.test", "certificate": chain, "key": key})).await;
    assert_eq!(r["msg"], "Success", "{r}");
    let host_dir = ssl_dir.join("mail.example.test");
    assert_eq!(read(&host_dir.join("fullchain.pem")).trim(), chain.trim());
    assert_eq!(
        std::fs::metadata(host_dir.join("privkey.pem"))
            .expect("key")
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "Go wrote keys 0755"
    );
    assert_eq!(
        read(&postfix.join("conf/vmail_ssl.map")),
        format!(
            "mail.example.test {ssl}/mail.example.test/privkey.pem {ssl}/mail.example.test/fullchain.pem\n"
        )
    );
    let conf = read(&dovecot);
    assert!(
        conf.contains(&format!(
            "#DOMAIN_SSL_BEGIN_mail.example.test\nlocal_name mail.example.test {{\n    ssl_cert = < {ssl}/mail.example.test/fullchain.pem\n"
        )),
        "{conf}"
    );
    let r = set(json!({"domain": "example.test", "certificate": chain, "key": ""})).await;
    assert_eq!(r["code"], 0, "an empty key keeps the stored one: {r}");

    let r = call(
        &app,
        "/api/domains/get_ssl?domain=example.test",
        &[("authorization", auth)],
        false,
    )
    .await;
    let data = &r.body["data"];
    assert_eq!(
        (
            data["subject"].clone(),
            data["key_pem"].clone(),
            data["dns"].clone()
        ),
        (
            json!("mail.example.test"),
            json!(""),
            json!(["mail.example.test"])
        ),
        "{}",
        r.body
    );
    assert!(data["endtime"].as_i64().is_some_and(|t| t > 0));
    assert!(data["not_after"].as_str().is_some_and(|d| d.len() == 10));
    let logs: String = sqlx::query_scalar(
        "SELECT COALESCE(string_agg(log || info, ' '), '') FROM bm_operation_logs",
    )
    .fetch_one(pg)
    .await
    .expect("logs");
    assert!(!logs.contains("PRIVATE KEY"), "Go logged the key");

    // --- Let's Encrypt is only asked for a host that resolves --------------------------
    let r = post(
        &app,
        "/api/ssl/apply_cert",
        auth,
        json!({"domain": "nope.test"}),
    )
    .await;
    assert_eq!(r.body["code"], 400);
    let r = post(
        &app,
        "/api/ssl/apply_cert",
        auth,
        json!({"domain": "other.test"}),
    )
    .await;
    assert_eq!(
        r.body["msg"], "A Record does not exist, please check DNS Settings: mail.other.test",
        "{}",
        r.body
    );
    let failure: (i32, String) = sqlx::query_as(
        "SELECT status, progress FROM letsencrypts WHERE subject = 'mail.other.test'",
    )
    .fetch_one(pg)
    .await
    .expect("failure recorded");
    assert_eq!(failure.0, -1);
    assert!(
        failure.1.starts_with("failed at "),
        "Go kept no time: {}",
        failure.1
    );
    let r = post(&app, "/api/ssl/console_apply_cert", auth, json!({})).await;
    assert_eq!(
        r.body["msg"],
        "Failed : BILLIONMAIL_HOSTNAME environment variable is not set"
    );
    let r = post(&app, "/api/ssl/get_cert_list", auth, json!({})).await;
    assert_eq!(r.body["code"], 501);

    // --- Renewals: a host that failed today is not tried again --------------------------
    ferropost_api::mail_tls::renew_all(&state)
        .await
        .expect("renew");
    let after: String =
        sqlx::query_scalar("SELECT progress FROM letsencrypts WHERE subject = 'mail.other.test'")
            .fetch_one(pg)
            .await
            .expect("progress");
    assert_eq!(after, failure.1, "backed off");
    let fresh = read(&host_dir.join("fullchain.pem"));
    assert_eq!(
        fresh.trim(),
        chain.trim(),
        "an uploaded certificate is kept until its last week"
    );

    // --- HTTP-01 challenges ----------------------------------------------------------------
    state
        .caches
        .acme_challenges
        .insert("tok-1".into(), "tok-1.thumbprint".into())
        .await;
    let r = call(&app, "/.well-known/acme-challenge/tok-1", &[], false).await;
    assert_eq!(r.body, json!("tok-1.thumbprint"));
    let r = call(&app, "/.well-known/acme-challenge/go-token", &[], false).await;
    assert_eq!(
        (r.body["go"].clone(), r.body["uri"].clone()),
        (json!(true), json!("/.well-known/acme-challenge/go-token")),
        "Go's own challenges still reach Go"
    );
}
