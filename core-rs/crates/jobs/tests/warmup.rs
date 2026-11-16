//! The hourly warmup pass against a real PostgreSQL. Runs only when
//! `FERROPOST_TEST_DATABASE_URL` is set; empties the database and applies
//! the store's migrations, so the tables are the real ones.
//! Expected scores and limits were computed with Go's expressions.

use ferropost_domain::warmup::DAY;
use ferropost_jobs::warmup::pass;
use sqlx::PgPool;

const NOW: i64 = 1_800_000_000;
const A: &str = "198.51.100.1";
const B: &str = "198.51.100.2";
const C: &str = "198.51.100.3";

async fn pool() -> Option<PgPool> {
    let url = std::env::var("FERROPOST_TEST_DATABASE_URL").ok()?;
    Some(PgPool::connect(&url).await.expect("connect"))
}

async fn reset(pg: &PgPool) {
    for sql in ["DROP SCHEMA public CASCADE", "CREATE SCHEMA public"] {
        sqlx::query(sql).execute(pg).await.expect(sql);
    }
    ferropost_store::migrate(pg).await.expect("migrations");
    let fixture = "INSERT INTO domain (domain, active) VALUES ('example.test', 1), ('off.test', 0)";
    sqlx::query(fixture).execute(pg).await.expect(fixture);
}

/// One logged message: sender, delivery status and DSN, minutes before NOW.
async fn message(pg: &PgPool, id: &str, sender: &str, status: &str, dsn: &str, ago_min: i64) {
    let at = (NOW - ago_min * 60) * 1000;
    sqlx::query("INSERT INTO mailstat_senders (postfix_message_id, log_time_millis, sender) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(at)
        .bind(sender)
        .execute(pg)
        .await
        .expect("sender");
    sqlx::query(
        "INSERT INTO mailstat_send_mails (postfix_message_id, log_time_millis, status, dsn, mail_provider)
         VALUES ($1, $2, $3, $4, 'google')",
    )
    .bind(id)
    .bind(at + 1000)
    .bind(status)
    .bind(dsn)
    .execute(pg)
    .await
    .expect("delivery");
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct Ip {
    period: i32,
    score: i32,
    progress: i32,
    re_warmups: i32,
    begin_time: i32,
    last_evaluate_time: i32,
}

async fn ip(pg: &PgPool, ip: &str) -> Ip {
    sqlx::query_as(
        "SELECT period, score, progress, re_warmups, begin_time, last_evaluate_time
           FROM bm_sender_ip_warmup WHERE sender_ip = $1",
    )
    .bind(ip)
    .fetch_one(pg)
    .await
    .expect("ip")
}

async fn provider(pg: &PgPool, ip: &str, group: &str) -> (i32, i32) {
    sqlx::query_as(
        "SELECT score, last_evaluate_time FROM bm_sender_ip_mail_provider
          WHERE sender_ip = $1 AND mail_provider = $2",
    )
    .bind(ip)
    .bind(group)
    .fetch_one(pg)
    .await
    .expect("provider")
}

async fn count(pg: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pg).await.expect(sql)
}

#[tokio::test]
async fn warmup_pass() {
    let Some(pg) = pool().await else {
        eprintln!("skipping: FERROPOST_TEST_DATABASE_URL not set");
        return;
    };
    reset(&pg).await;
    let t = |offset: i64| (NOW + offset) as i32;
    for (sender_ip, period, score, progress, last_eval, begin, create, update) in [
        // In warmup for 10 days, due for evaluation.
        (A, 45, 40, 0, t(-7200), t(-10 * DAY), t(-10 * DAY), t(-7200)),
        // Finished and healthy: stays finished (Go undid it in the same pass).
        (
            B,
            0,
            60,
            100,
            t(-1800),
            t(-60 * DAY),
            t(-60 * DAY),
            t(-3600),
        ),
        // Finished but its reputation dropped: starts over.
        (
            C,
            0,
            30,
            100,
            t(-1800),
            t(-60 * DAY),
            t(-60 * DAY),
            t(-3600),
        ),
    ] {
        sqlx::query(
            "INSERT INTO bm_sender_ip_warmup (sender_ip, period, score, progress, last_evaluate_time,
                 begin_time, end_time, create_time, update_time)
             VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8)",
        )
        .bind(sender_ip)
        .bind(period)
        .bind(score)
        .bind(progress)
        .bind(last_eval)
        .bind(begin)
        .bind(create)
        .bind(update)
        .execute(&pg)
        .await
        .expect("ip");
    }
    // Provider groups of A that are due; the rest are created by the pass.
    for group in ["google", "yahoo"] {
        sqlx::query(
            "INSERT INTO bm_sender_ip_mail_provider (sender_ip, mail_provider, score,
                 last_evaluate_time, create_time, update_time) VALUES ($1, $2, 40, $3, $4, $4)",
        )
        .bind(A)
        .bind(group)
        .bind(t(-3 * 3600))
        .bind(t(-DAY))
        .execute(&pg)
        .await
        .expect("provider");
    }

    // 25 messages from an active domain in the window: 23 delivered, one
    // hard bounce, one deferral; 10 opened (one twice), 2 clicked, one
    // complaint.
    for i in 0..25 {
        let (status, dsn) = match i {
            0 => ("bounced", "5.1.1"),
            1 => ("deferred", "4.4.1"),
            _ => ("sent", "2.0.0"),
        };
        message(
            &pg,
            &format!("Q{i}"),
            "news@example.test",
            status,
            dsn,
            60 + i,
        )
        .await;
    }
    // Not counted: an inactive domain, and mail before the window.
    for i in 0..3 {
        message(
            &pg,
            &format!("OFF{i}"),
            "x@off.test",
            "bounced",
            "5.0.0",
            30,
        )
        .await;
        message(
            &pg,
            &format!("OLD{i}"),
            "news@example.test",
            "bounced",
            "5.0.0",
            8 * 24 * 60,
        )
        .await;
    }
    for i in 2..12 {
        sqlx::query(
            "INSERT INTO mailstat_opened (postfix_message_id, log_time_millis) VALUES ($1, $2)",
        )
        .bind(format!("Q{i}"))
        .bind((NOW - 10) * 1000)
        .execute(&pg)
        .await
        .expect("open");
    }
    for sql in [
        "INSERT INTO mailstat_opened (postfix_message_id, log_time_millis) VALUES ('Q2', 1799999990000)",
        "INSERT INTO mailstat_clicked (postfix_message_id, log_time_millis)
            VALUES ('Q2', 1799999990000), ('Q3', 1799999990000)",
        "INSERT INTO mailstat_complaints (postfix_message_id, log_time_millis)
            VALUES ('Q4', 1799999990000)",
    ] {
        sqlx::query(sql).execute(&pg).await.expect(sql);
    }

    // Another process holds the pass lock: nothing happens.
    let mut other = pg.acquire().await.expect("conn");
    sqlx::query("SELECT pg_advisory_lock(hashtext('ferropost:warmup-pass'))")
        .execute(&mut *other)
        .await
        .expect("lock");
    pass(&pg, NOW).await.expect("skipped pass");
    assert_eq!(ip(&pg, A).await.score, 40);
    sqlx::query("SELECT pg_advisory_unlock(hashtext('ferropost:warmup-pass'))")
        .execute(&mut *other)
        .await
        .expect("unlock");
    drop(other);

    pass(&pg, NOW).await.expect("pass");

    // A: 40 + 3.6 - 0.4 - 0.08 + 10/23*20 + 2/10*15 = 54.8; 10 of 45 days.
    assert_eq!(
        ip(&pg, A).await,
        Ip {
            period: 45,
            score: 54,
            progress: 22,
            re_warmups: 0,
            begin_time: t(-10 * DAY),
            last_evaluate_time: t(0),
        }
    );
    let b = ip(&pg, B).await;
    assert_eq!(
        (b.period, b.progress, b.score),
        (0, 100, 60),
        "finished stays finished"
    );
    let c = ip(&pg, C).await;
    assert_eq!(
        (c.period, c.progress, c.re_warmups, c.begin_time),
        (60, 0, 1, t(0)),
        "re-warmup"
    );

    // google: 40 + 2.8 - 0.06 - 0.01 + 10/23*25 + 4 - 1/23*200 = 48.9.
    assert_eq!(provider(&pg, A, "google").await, (48, t(0)));
    // yahoo: due, but nothing sent there and A is early in its warmup.
    assert_eq!(provider(&pg, A, "yahoo").await, (40, t(0)));
    // Every IP gets one row per provider group.
    assert_eq!(
        count(&pg, "SELECT COUNT(*) FROM bm_sender_ip_mail_provider").await,
        24
    );

    // A second pass at the same moment changes nothing and adds no rows.
    pass(&pg, NOW).await.expect("second pass");
    assert_eq!(ip(&pg, A).await.score, 54);
    assert_eq!(provider(&pg, A, "google").await, (48, t(0)));
    assert_eq!(
        count(&pg, "SELECT COUNT(*) FROM bm_sender_ip_mail_provider").await,
        24
    );
    assert_eq!(
        count(&pg, "SELECT COUNT(*) FROM bm_sender_ip_warmup").await,
        3
    );

    // Limits on day 11 (28561/2856 a day/hour) scaled by the group score.
    let limits = |ip: &'static str, group: &'static str| {
        let pg = pg.clone();
        async move {
            ferropost_store::warmup::limits(&pg, ip, group, NOW)
                .await
                .expect("limits")
        }
    };
    assert_eq!(limits(A, "google").await, (10_739, 1074));
    assert_eq!(limits(A, "zoho").await, (7998, 800));
    // A new IP starts its warmup on day 1.
    assert_eq!(limits("203.0.113.7", "google").await, (280, 29));
    assert_eq!(
        count(&pg, "SELECT COUNT(*) FROM bm_sender_ip_warmup").await,
        4
    );
}
