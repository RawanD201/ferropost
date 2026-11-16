//! The rspamd web interface: admins' API calls set a cookie bound to their
//! login session; with it, `/rspamd/*` reaches the controller with its
//! password and without the console's credentials; logout, a tampered
//! cookie or a lost admin role end access.

mod common;

use axum::Router;
use common::*;
use serde_json::{Value, json};

/// A stand-in rspamd controller that answers with what it received.
async fn fake_rspamd() -> String {
    async fn echo(req: axum::extract::Request) -> axum::Json<Value> {
        let header = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        axum::Json(json!({
            "method": req.method().as_str(),
            "uri": req.uri().to_string(),
            "password": header("password"),
            "cookie": header("cookie"),
            "authorization": header("authorization"),
        }))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, Router::new().fallback(echo)).await });
    format!("http://{addr}")
}

fn rspamd_cookie(reply: &Reply) -> Option<String> {
    reply
        .headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("ferropost_rspamd="))
        .map(str::to_owned)
}

#[tokio::test]
async fn rspamd_proxy() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    sqlx::query(
        "INSERT INTO bm_options (name, value) VALUES ('rspamd_worker_controller_password', 'ctl-pw')",
    )
    .execute(pg)
    .await
    .expect("password");
    let target = fake_rspamd().await;
    let env = [("FERROPOST_RSPAMD_URL", target.as_str())];
    let app = h.app(&env);

    let r = call(&app, "/rspamd/", &[], false).await;
    assert_eq!(
        (r.status.as_u16(), r.body.as_str()),
        (403, Some("Access denied"))
    );

    // An admin's login session, as issued by /api/login.
    let state = h.state(&env);
    let pair = state
        .jwt
        .issue_pair(1, "admin", &["admin".to_owned()], "sess-rspamd");
    let access = bearer(&pair.token);
    let r = call(
        &app,
        "/api/tags/list?page=1&page_size=10",
        &[("authorization", &access)],
        true,
    )
    .await;
    let set = rspamd_cookie(&r).expect("an admin gets the cookie");
    assert!(
        set.contains("; Path=/rspamd;")
            && set.contains("; HttpOnly")
            && set.contains("SameSite=Strict")
            && set.ends_with("; Secure"),
        "{set}"
    );
    let cookie = set.split(';').next().expect("pair").to_owned();
    let r = call(
        &app,
        "/api/tags/list?page=1&page_size=10",
        &[("authorization", &access), ("cookie", &cookie)],
        true,
    )
    .await;
    assert_eq!(rspamd_cookie(&r), None, "a current cookie is not reissued");
    let viewer = bearer(&token(2, "access_token", "viewer-rspamd"));
    let r = call(
        &app,
        "/api/tags/list?page=1&page_size=10",
        &[("authorization", &viewer)],
        false,
    )
    .await;
    assert_eq!(rspamd_cookie(&r), None, "only admins");

    // Through to the controller, with its password and none of ours.
    let r = call(
        &app,
        "/rspamd/stat?x=1",
        &[("cookie", &cookie), ("authorization", "Bearer other")],
        false,
    )
    .await;
    assert_eq!(
        r.body,
        json!({"method": "GET", "uri": "/stat?x=1", "password": "ctl-pw", "cookie": null, "authorization": null}),
        "{}",
        r.body
    );
    let r = call(&app, "/rspamd", &[("cookie", &cookie)], false).await;
    assert_eq!(r.body["uri"], "/");
    let r = send(
        &app,
        "POST",
        "/rspamd/learnspam",
        &[("cookie", &cookie)],
        Some(json!({})),
        false,
    )
    .await;
    assert_eq!(r.body["method"], "POST");

    let tampered = cookie.replacen("ferropost_rspamd=1.", "ferropost_rspamd=2.", 1);
    let r = call(&app, "/rspamd/", &[("cookie", &tampered)], false).await;
    assert_eq!(r.status.as_u16(), 403, "another account");

    // Losing the admin role ends access (fresh caches see it at once).
    sqlx::query("UPDATE account_role SET role_id = 2 WHERE account_id = 1")
        .execute(pg)
        .await
        .expect("demote");
    let demoted = h.app(&env);
    let r = call(&demoted, "/rspamd/", &[("cookie", &cookie)], false).await;
    assert_eq!(r.status.as_u16(), 403, "no longer an admin");
    sqlx::query("UPDATE account_role SET role_id = 1 WHERE account_id = 1")
        .execute(pg)
        .await
        .expect("restore");

    // Logout clears the cookie and ends the session it is bound to.
    let fresh = h.app(&env);
    let r = send(
        &fresh,
        "POST",
        "/api/logout",
        &[("authorization", &access)],
        Some(json!({})),
        false,
    )
    .await;
    assert_eq!(r.body["msg"], "Logout successful");
    assert!(rspamd_cookie(&r).is_some_and(|c| c.contains("Max-Age=0")));
    let r = call(&fresh, "/rspamd/", &[("cookie", &cookie)], false).await;
    assert_eq!(r.status.as_u16(), 403, "logged out");
}
