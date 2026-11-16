//! End-to-end tests for open and click tracking links.

mod common;

use axum::http::{StatusCode, header};
use common::*;
use ferropost_domain::tracking::{EventKind, TrackingEvent, encode_legacy};
use serde_json::json;

fn token(kind: EventKind, message_id: &str, url: &str, campaign_id: i64) -> String {
    encode_legacy(
        &TrackingEvent {
            kind,
            campaign_id,
            recipient: "a@x.com".into(),
            message_id: message_id.into(),
            url: url.into(),
        },
        [5; 16],
        [6; 16],
    )
}

#[tokio::test]
async fn tracking_links() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let app = h.app(&[]);
    for sql in [
        "INSERT INTO mailstat_message_ids (postfix_message_id, message_id) VALUES ('PQ1', 'm1@mail.x.com')",
        "INSERT INTO email_tasks (id, task_name, group_id, addresser, recipient_count, template_id)
            VALUES (12, 'Promo', 1, 'news@x.com', 1, 0)",
        "INSERT INTO bm_contacts (id, email, group_id, last_active_at) VALUES
            (10, 'a@x.com', 1, 0), (11, 'a@x.com', 2, 0)",
    ] {
        sqlx::query(sql).execute(&h.store.pg).await.expect(sql);
    }
    let get = |uri: String| {
        let app = app.clone();
        async move { call(&app, &uri, &[], false).await }
    };
    let count = |table: &'static str| {
        let pg = h.store.pg.clone();
        async move {
            sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&pg)
                .await
                .expect("count")
        }
    };

    // Open: pixel, event, and the campaign's group marked active.
    let r = get(format!(
        "/pmta/{}",
        token(EventKind::Open, "m1@mail.x.com", "", 12)
    ))
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers[header::CONTENT_TYPE], "image/png");
    assert_eq!(count("mailstat_opened").await, 1);
    let active: Vec<(i32, i32)> =
        sqlx::query_as("SELECT group_id, last_active_at FROM bm_contacts ORDER BY group_id")
            .fetch_all(&h.store.pg)
            .await
            .expect("contacts");
    assert!(
        active[0].1 > 0 && active[1].1 == 0,
        "only the campaign's group: {active:?}"
    );

    // Click: redirect and the URL is kept.
    let r = get(format!(
        "/pmta/{}",
        token(
            EventKind::Click,
            "m1@mail.x.com",
            "https://example.com/sale",
            12
        )
    ))
    .await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(r.headers[header::LOCATION], "https://example.com/sale");
    let url: String = sqlx::query_scalar("SELECT url FROM mailstat_clicked")
        .fetch_one(&h.store.pg)
        .await
        .expect("click");
    assert_eq!(url, "https://example.com/sale");

    // Forged tokens with an unknown message ID neither count nor redirect.
    let r = get(format!(
        "/pmta/{}",
        token(EventKind::Click, "forged@evil", "https://evil.example", 12)
    ))
    .await;
    assert_eq!(
        (r.status, r.body.clone()),
        (StatusCode::OK, json!("Invalid -3"))
    );
    assert_eq!(count("mailstat_clicked").await, 1);
    let r = get(format!(
        "/pmta/{}",
        token(EventKind::Open, "forged@evil", "", 12)
    ))
    .await;
    assert_eq!(
        r.headers[header::CONTENT_TYPE],
        "image/png",
        "pixel still served"
    );
    assert_eq!(count("mailstat_opened").await, 1);

    // Non-web URLs and garbage are rejected.
    let r = get(format!(
        "/pmta/{}",
        token(EventKind::Click, "m1@mail.x.com", "javascript:alert(1)", 12)
    ))
    .await;
    assert_eq!(r.body, json!("Invalid -2"));
    assert_eq!(get("/pmta/garbage".into()).await.body, json!("Invalid -1"));

    // API sends (campaign above 1e9) mark every group active.
    get(format!(
        "/pmta/{}",
        token(EventKind::Open, "m1@mail.x.com", "", 2_000_000_000)
    ))
    .await;
    let untouched: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM bm_contacts WHERE last_active_at = 0")
            .fetch_one(&h.store.pg)
            .await
            .expect("count");
    assert_eq!(untouched, 0);
}
