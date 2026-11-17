//! The schema migration: a second run changes nothing, a migration from a
//! newer core does not stop it, its SQL applies to a database Go already
//! made, and relays of installs older than `bm_relay_config` are moved
//! (once).

mod common;

use common::*;

const SCHEMA: &str = include_str!("../../store/migrations/0001_schema.sql");

#[tokio::test]
async fn schema() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    ferropost_store::migrate(pg).await.expect("second run");
    // After a rollback: a migration only a newer core knows is left alone.
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
         VALUES (99990101000000, 'from a newer core', true, '\\x00', 0)",
    )
    .execute(pg)
    .await
    .expect("newer migration");
    ferropost_store::migrate(pg)
        .await
        .expect("starts on a newer schema");
    // A database Go made has every table: the SQL runs over it unchanged.
    sqlx::raw_sql(SCHEMA)
        .execute(pg)
        .await
        .expect("over an existing schema");

    sqlx::raw_sql(
        "CREATE TABLE bm_relay (
            id BIGSERIAL PRIMARY KEY, remark varchar(255), rtype varchar(30),
            sender_domain varchar(255) NOT NULL, relay_host varchar(255) NOT NULL,
            relay_port varchar(10) NOT NULL, auth_user varchar(255) NOT NULL,
            auth_password varchar(255) NOT NULL, ip varchar(255), host varchar(255),
            create_time int NOT NULL default 0, update_time int NOT NULL default 0,
            active smallint NOT NULL DEFAULT 1, auth_method varchar(20),
            skip_tls_verify smallint DEFAULT 0, helo_name varchar(255), smtp_name varchar(50));
         INSERT INTO bm_relay (sender_domain, relay_host, relay_port, auth_user, auth_password, create_time)
         VALUES ('@old.test', 'smtp.relay.test', '', 'user', 'pw', 5),
                ('', 'bare.relay.test', '2525', 'u2', 'p2', 6)",
    )
    .execute(pg)
    .await
    .expect("old relays");
    sqlx::raw_sql(SCHEMA)
        .execute(pg)
        .await
        .expect("move old relays");
    let moved: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT relay_host, relay_port, smtp_name, auth_method FROM bm_relay_config ORDER BY id",
    )
    .fetch_all(pg)
    .await
    .expect("relays");
    assert_eq!(
        moved,
        [
            (
                "smtp.relay.test".to_owned(),
                "25".to_owned(),
                "MigratedRelay_1_smtp_relay_test".to_owned(),
                "LOGIN".to_owned()
            ),
            (
                "bare.relay.test".to_owned(),
                "2525".to_owned(),
                "MigratedRelay_2_bare_relay_test".to_owned(),
                "LOGIN".to_owned()
            ),
        ]
    );
    let mapped: Vec<String> =
        sqlx::query_scalar("SELECT sender_domain FROM bm_relay_domain_mapping")
            .fetch_all(pg)
            .await
            .expect("mappings");
    assert_eq!(mapped, ["@old.test"]);
    sqlx::raw_sql(SCHEMA).execute(pg).await.expect("once only");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM bm_relay_config")
        .fetch_one(pg)
        .await
        .expect("count");
    assert_eq!(count, 2);

    // An old table the migration cannot read does not stop the core.
    sqlx::raw_sql(
        "DELETE FROM bm_relay_domain_mapping; DELETE FROM bm_relay_config;
         DROP TABLE bm_relay; CREATE TABLE bm_relay (id SERIAL PRIMARY KEY, relay_host TEXT);
         INSERT INTO bm_relay (relay_host) VALUES ('x.test')",
    )
    .execute(pg)
    .await
    .expect("broken old table");
    sqlx::raw_sql(SCHEMA)
        .execute(pg)
        .await
        .expect("still applies");
}
