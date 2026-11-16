//! Mail-log ingestion against a real PostgreSQL. Runs only when
//! `FERROPOST_TEST_DATABASE_URL` is set; empties the database and applies
//! the store's migrations, so the tables are the real ones.

use std::io::Write;
use std::path::Path;

use ferropost_jobs::maillog::Tailer;
use sqlx::PgPool;

async fn pool() -> Option<PgPool> {
    let url = std::env::var("FERROPOST_TEST_DATABASE_URL").ok()?;
    Some(PgPool::connect(&url).await.expect("connect"))
}

async fn reset(pg: &PgPool) {
    for sql in ["DROP SCHEMA public CASCADE", "CREATE SCHEMA public"] {
        sqlx::query(sql).execute(pg).await.expect(sql);
    }
    ferropost_store::migrate(pg).await.expect("migrations");
    let fixture = "INSERT INTO domain (domain) VALUES ('ex.com')";
    sqlx::query(fixture).execute(pg).await.expect(fixture);
}

fn append(path: &Path, text: &str) {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .expect("append");
}

async fn count(pg: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pg).await.expect(sql)
}

async fn drain(tailer: &Tailer) {
    while tailer.tick().await.expect("tick") {}
}

#[tokio::test]
async fn ingests_mail_log() {
    let Some(pg) = pool().await else {
        eprintln!("skipping: FERROPOST_TEST_DATABASE_URL not set");
        return;
    };
    reset(&pg).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("mail.log");
    let tailer = Tailer::new(log.clone(), dir.path().join("main.cf"), pg.clone());

    // Go already processed everything up to 10:00:00.
    sqlx::query("INSERT INTO bm_options VALUES ('last_maillog_time_millis', '1763200800000')")
        .execute(&pg)
        .await
        .expect("watermark");
    append(
        &log,
        "2025-11-15T09:59:00Z mail postfix/qmgr[1]: OLD1: removed\n\
         2025-11-15T10:00:01Z mail postfix/cleanup[1]: Q1: message-id=<m1@ex.com>\n\
         2025-11-15T10:00:01Z mail postfix/qmgr[1]: Q1: from=<news@ex.com>, size=900, nrcpt=2 (queue active)\n\
         2025-11-15T10:00:02Z mail postfix/smtp[2]: Q1: to=<bob@gmail.com>, relay=mx.google.com[1.2.3.4]:25, delay=1, delays=0/0/0.5/0.5, dsn=4.2.0, status=deferred (try later)\n",
    );
    drain(&tailer).await;
    assert_eq!(
        count(&pg, "SELECT COUNT(*) FROM mailstat_removed").await,
        0,
        "Go's history is not repeated"
    );
    assert_eq!(
        count(&pg, "SELECT COUNT(*) FROM mailstat_deferred_mails").await,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM mailstat_send_mails WHERE postfix_message_id = 'Q1'"
        )
        .fetch_one(&pg)
        .await
        .expect("send"),
        "deferred"
    );

    // Nothing new: ticking again changes nothing (Go re-read the last second
    // and inserted the deferral again).
    drain(&tailer).await;
    assert_eq!(
        count(&pg, "SELECT COUNT(*) FROM mailstat_deferred_mails").await,
        1
    );

    // The retry succeeds; a local delivery between own domains arrives too.
    append(
        &log,
        "2025-11-15T10:05:00Z mail postfix/smtp[2]: Q1: to=<bob@gmail.com>, relay=mx.google.com[1.2.3.4]:25, delay=300, delays=0/0/0.5/0.5, dsn=2.0.0, status=sent (250 ok)\n\
         2025-11-15T10:05:01Z mail postfix/qmgr[1]: Q1: removed\n\
         2025-11-15T10:06:00Z mail postfix/qmgr[1]: L1: from=<news@ex.com>, size=100, nrcpt=1 (queue active)\n\
         2025-11-15T10:06:01Z mail postfix/lmtp[3]: L1: to=<alice@ex.com>, relay=mail.ex.com[private/dovecot-lmtp], delay=0.1, delays=0/0/0/0.1, dsn=2.0.0, status=sent (250 ok)\n\
         2025-11-15T10:06:02Z mail postfix/qmgr[1]: Q9: rem",
    );
    drain(&tailer).await;
    let (status, provider, dsn): (String, String, String) = sqlx::query_as(
        "SELECT status, mail_provider, dsn FROM mailstat_send_mails WHERE postfix_message_id = 'Q1'",
    )
    .fetch_one(&pg)
    .await
    .expect("send");
    assert_eq!(
        (status.as_str(), provider.as_str(), dsn.as_str()),
        ("sent", "google", "2.0.0")
    );
    assert_eq!(
        count(&pg, "SELECT COUNT(*) FROM mailstat_receive_mails").await,
        1
    );
    assert_eq!(
        count(&pg, "SELECT COUNT(*) FROM mailstat_removed").await,
        1,
        "partial line waits"
    );

    // Rotation: the rest of the old file is read before the new one.
    append(&log, "oved\n");
    std::fs::rename(&log, dir.path().join("mail.log.1")).expect("rotate");
    append(
        &log,
        "2025-11-15T11:00:00Z mail postfix/qmgr[1]: N1: removed\n",
    );
    drain(&tailer).await;
    assert_eq!(
        count(&pg, "SELECT COUNT(*) FROM mailstat_removed").await,
        3,
        "Q1, Q9 and N1"
    );

    // Local deliveries between own domains count as sent mail.
    let added = ferropost_store::maillog::aggregate_local(&pg, 1_763_210_000_000)
        .await
        .expect("aggregate");
    assert_eq!(added, 1);
    let provider: String = sqlx::query_scalar(
        "SELECT mail_provider FROM mailstat_send_mails WHERE postfix_message_id = 'L1'",
    )
    .fetch_one(&pg)
    .await
    .expect("local");
    assert_eq!(provider, "local");
    assert_eq!(
        ferropost_store::maillog::aggregate_local(&pg, 1_763_210_000_000)
            .await
            .expect("again"),
        0
    );

    let watermark: String =
        sqlx::query_scalar("SELECT value FROM bm_options WHERE name = 'last_maillog_time_millis'")
            .fetch_one(&pg)
            .await
            .expect("watermark");
    assert_eq!(watermark, "1763204400000", "Go's watermark follows along");
}
