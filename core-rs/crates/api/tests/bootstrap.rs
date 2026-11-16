//! Start-up work: the administrator's login from `.env` (what
//! `bm.sh change-password` relies on), the first API token and the
//! console's self-signed certificate.

mod common;

use common::*;

async fn admin(pg: &sqlx::PgPool) -> (i32, String, String) {
    sqlx::query_as(
        "SELECT a.account_id, a.username, a.password FROM account a
           JOIN account_role ar ON ar.account_id = a.account_id
           JOIN role r ON r.role_id = ar.role_id WHERE r.role_name = 'admin'
          ORDER BY a.account_id LIMIT 1",
    )
    .fetch_one(pg)
    .await
    .expect("admin")
}

#[tokio::test]
async fn bootstrap() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    let ssl = h.root.path().join("ssl");
    let ssl_dir = ssl.display().to_string();
    let state = h.state(&[
        ("ADMIN_USERNAME", "root"),
        ("ADMIN_PASSWORD", "secret123"),
        ("FERROPOST_SSL_DIR", &ssl_dir),
    ]);

    // An existing install: the administrator takes the login from .env.
    ferropost_api::bootstrap::admin_account(&state)
        .await
        .expect("sync");
    let (id, username, hash) = admin(pg).await;
    assert_eq!((id, username.as_str()), (1, "root"));
    assert!(pwhash::bcrypt::verify("secret123", &hash));
    ferropost_api::bootstrap::admin_account(&state)
        .await
        .expect("again");
    assert_eq!(
        admin(pg).await.2,
        hash,
        "an unchanged password is not hashed again (Go re-hashed at every start)"
    );

    ferropost_api::bootstrap::api_token(&state)
        .await
        .expect("token");
    let token: String = sqlx::query_scalar("SELECT value FROM bm_options WHERE name = 'API_TOKEN'")
        .fetch_one(pg)
        .await
        .expect("API_TOKEN");
    assert!(state.jwt.verify(&token).is_some_and(|c| c.api_token));
    ferropost_api::bootstrap::api_token(&state)
        .await
        .expect("kept");
    let again: String = sqlx::query_scalar("SELECT value FROM bm_options WHERE name = 'API_TOKEN'")
        .fetch_one(pg)
        .await
        .expect("API_TOKEN");
    assert_eq!(again, token, "issued once");

    // A new install: the account is made.
    sqlx::raw_sql("DELETE FROM account_role; DELETE FROM account; DELETE FROM role")
        .execute(pg)
        .await
        .expect("empty");
    ferropost_api::bootstrap::admin_account(&state)
        .await
        .expect("create");
    let (_, username, hash) = admin(pg).await;
    assert_eq!(username, "root");
    assert!(pwhash::bcrypt::verify("secret123", &hash));

    // The console's certificate, when there is none.
    ferropost_api::bootstrap::console_certificate(&state)
        .await
        .expect("certificate");
    assert!(ssl.join("cert.pem").exists());
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(ssl.join("key.pem"))
            .expect("key")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "Go wrote the key 0777");
    }
    let cert = std::fs::read(ssl.join("cert.pem")).expect("cert");
    ferropost_api::bootstrap::console_certificate(&state)
        .await
        .expect("kept");
    assert_eq!(
        std::fs::read(ssl.join("cert.pem")).expect("cert"),
        cert,
        "an existing one is kept"
    );

    // No rspamd container here: nothing to set.
    ferropost_api::bootstrap::rspamd_controller(&state)
        .await
        .expect("controller");
}
