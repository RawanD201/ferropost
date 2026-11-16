//! End-to-end tests for the sending dashboard.

mod common;

use common::*;
use serde_json::json;

const START: i64 = 1_763_164_800; // 2025-11-15T00:00:00Z
const H: i64 = 3_600;
const D: i64 = 86_400;

#[tokio::test]
async fn overview_dashboard() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let app = h.app(&[]);
    let admin = bearer(&token(1, "access_token", "admin-overview"));
    let ms = |t: i64| t * 1000;
    for sql in [
        format!(
            "INSERT INTO mailstat_send_mails (postfix_message_id, log_time_millis, status, recipient, mail_provider, dsn, delay) VALUES
                ('P1', {}, 'sent', 'a@gmail.com', 'google', '2.0.0', 1.5),
                ('P2', {}, 'bounced', 'b@gmail.com', 'google', '5.1.1', 0.2),
                ('P3', {}, 'deferred', 'c@outlook.com', 'outlook', '4.2.0', 3),
                ('P4', {}, 'sent', 'd@outlook.com', 'outlook', '2.0.0', 1),
                ('P5', {}, 'sent', 'e@gmail.com', 'google', '2.0.0', 1)",
            ms(START + H),
            ms(START + 2 * H),
            ms(START + D + H),
            ms(START + D),
            ms(START - 10)
        ),
        "INSERT INTO mailstat_senders (postfix_message_id, sender) VALUES
            ('P1', 'news@ex.com'), ('P2', 'news@ex.com'), ('P3', 'news@ex.com'),
            ('P4', 'other@other.com'), ('P5', 'news@ex.com')"
            .to_owned(),
        "INSERT INTO mailstat_opened (postfix_message_id) VALUES ('P1'), ('P1')".to_owned(),
        "INSERT INTO mailstat_clicked (postfix_message_id) VALUES ('P1')".to_owned(),
        "INSERT INTO mailstat_message_ids (postfix_message_id, message_id) VALUES ('P1', 'm1')".to_owned(),
        // Two recipient rows on one message (Go's join counted it twice).
        "INSERT INTO recipient_info (task_id, recipient, message_id) VALUES (7, 'a@gmail.com', 'm1'), (7, 'b@gmail.com', 'm1')"
            .to_owned(),
        "INSERT INTO mailstat_deferred_mails (postfix_message_id, dsn, description) VALUES
            ('P3', '4.2.0', 'first'), ('P3', '4.4.1', 'latest')"
            .to_owned(),
    ] {
        sqlx::query(&sql).execute(&h.store.pg).await.expect("seed");
    }
    let get = |query: String| {
        let (app, admin) = (app.clone(), admin.clone());
        async move {
            call(
                &app,
                &format!("/api/overview{query}"),
                &[("authorization", &admin)],
                false,
            )
            .await
        }
    };
    let window = |start: i64, end: i64| format!("start_time={start}&end_time={end}");

    // --- dashboard and providers ------------------------------------------
    let r = get(format!("?{}", window(START, START + 3 * D))).await;
    assert_eq!(r.body["msg"], "Success");
    let d = &r.body["data"]["dashboard"];
    assert_eq!(
        (
            d["sends"].clone(),
            d["delivered"].clone(),
            d["bounced"].clone(),
            d["opened"].clone(),
            d["clicked"].clone()
        ),
        (json!(4), json!(2), json!(1), json!(1), json!(1)),
        "P5 is outside the window; P1's two opens count once"
    );
    assert_eq!(
        (
            d["delivery_rate"].clone(),
            d["bounce_rate"].clone(),
            d["open_rate"].clone(),
            d["click_rate"].clone()
        ),
        (json!(50.0), json!(25.0), json!(50.0), json!(50.0))
    );
    let providers = r.body["data"]["mail_providers"]
        .as_array()
        .expect("providers");
    assert_eq!(providers.len(), 2);
    assert_eq!(providers[0]["mail_provider"], "google");
    assert_eq!(providers[0]["bounce_rate"], 50.0);

    // --- daily chart: every day of the window, in order --------------------
    let chart = &r.body["data"]["send_mail_chart"];
    assert_eq!(chart["column_type"], "daily");
    let xs: Vec<i64> = chart["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|p| p["x"].as_i64().expect("x"))
        .collect();
    assert_eq!(xs, [START, START + D, START + 2 * D, START + 3 * D]);
    assert_eq!(
        chart["data"][0],
        json!({"x": START, "sends": 2, "delivered": 1, "failed": 1})
    );
    assert_eq!(chart["data"][1]["sends"], 2);
    assert_eq!(chart["dashboard"]["failure_rate"], 50.0);
    assert_eq!(
        r.body["data"]["bounce_rate_chart"]["data"][0],
        json!({"x": START, "bounce_rate": 50.0})
    );
    assert_eq!(
        r.body["data"]["open_rate_chart"]["data"][0]["open_rate"],
        100.0
    );
    assert_eq!(
        r.body["data"]["click_rate_chart"]["data"][0]["click_rate"],
        100.0
    );

    // --- other bucket sizes -------------------------------------------------
    let r = get(format!("?{}", window(START, START + 3 * H))).await;
    let hourly = &r.body["data"]["send_mail_chart"];
    assert_eq!(hourly["column_type"], "hourly");
    assert_eq!(hourly["data"].as_array().expect("data").len(), 24);
    assert_eq!(hourly["data"][1]["sends"], 1);
    assert_eq!(hourly["data"][2]["sends"], 1);

    let r = get(format!("?{}", window(START - 60 * D, START + 3 * D))).await;
    let monthly = &r.body["data"]["send_mail_chart"];
    assert_eq!(monthly["column_type"], "monthly");
    let months: Vec<i64> = monthly["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|p| p["x"].as_i64().expect("x"))
        .collect();
    assert_eq!(
        months,
        [1_756_684_800, 1_759_276_800, 1_761_955_200],
        "Sep, Oct and Nov 1st"
    );

    // --- filters --------------------------------------------------------------
    let sends = |r: &Reply| {
        r.body["data"]["dashboard"]["sends"]
            .as_i64()
            .expect("sends")
    };
    assert_eq!(
        sends(&get(format!("?{}&domain=ex.com", window(START, START + 3 * D))).await),
        3
    );
    assert_eq!(
        sends(&get(format!("?{}&campaign_id=7", window(START, START + 3 * D))).await),
        1,
        "two recipient rows for one message count once"
    );

    // --- failed list ----------------------------------------------------------
    let r = call(
        &app,
        &format!("/api/overview/failed?{}", window(START, START + 3 * D)),
        &[("authorization", &admin)],
        false,
    )
    .await;
    let failed = r.body["data"].as_array().expect("failed");
    assert_eq!(failed.len(), 2);
    assert_eq!(failed[0]["postfix_message_id"], "P3", "newest first");
    assert_eq!(failed[0]["dsn"], "4.4.1", "latest deferral");
    assert_eq!(failed[0]["description"], "latest");
    assert_eq!(failed[1]["status"], "bounced");
    assert_eq!(failed[1]["delay"], "0.2");
    assert_eq!(failed[1]["log_time"], (START + 2 * H).to_string());

    // --- validation -----------------------------------------------------------
    assert_eq!(get("?end_time=10".into()).await.body["code"], 412);
    assert_eq!(
        get(format!("?{}", window(START, START - 1))).await.body["code"],
        412
    );
    assert_eq!(
        get(format!(
            "?{}&domain=not%20a%20domain",
            window(START, START + D)
        ))
        .await
        .body["code"],
        412
    );
}
