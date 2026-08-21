mod common;

use ioc_graph_backend::{db, ingest::load_dashboard_snapshot, models::GraphSnapshot};
use uuid::Uuid;

use common::{domain, record, record_with_context, DashboardFixture, SyntheticContext};

#[tokio::test]
#[ignore = "requires Docker daemon for PostgreSQL Testcontainers"]
async fn postgres_contract_supports_snapshot_upsert_delete_and_constraints() {
    use testcontainers_modules::{postgres, testcontainers::runners::AsyncRunner};

    let container = postgres::Postgres::default()
        .start()
        .await
        .expect("start postgres testcontainer");
    let host = container.get_host().await.expect("postgres host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("postgres port");
    let database_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let pool = db::connect(&database_url).await.expect("connect postgres");
    db::migrate(&pool).await.expect("run migrations");

    let dashboard = DashboardFixture::new();
    dashboard.write_records("iocs.json", &[record(1, "domain", domain(1))]);
    let initial = load_dashboard_snapshot(dashboard.path()).expect("load initial dashboard");
    db::replace_snapshot(&pool, &initial)
        .await
        .expect("insert snapshot");
    assert_table_count_at_least(&pool, "nodes", 1).await;
    assert_table_count_at_least(&pool, "edges", 1).await;
    assert_table_count_at_least(&pool, "alerts", 1).await;
    assert_ingested_file(&pool, &initial.source_files[0], true).await;
    assert_observation_constraints(&pool, &initial.source_files[0].path).await;
    assert_legacy_alert_identity_is_reconciled(&pool, &initial).await;

    dashboard.write_records(
        "iocs.json",
        &[record_with_context(
            2,
            "domain",
            domain(1),
            SyntheticContext::indexed(2)
                .first_seen("2026-01-01T00:00:00Z")
                .last_seen("2026-01-02T00:00:00Z")
                .alert_id("same-domain-updated"),
        )],
    );
    let updated = load_dashboard_snapshot(dashboard.path()).expect("load updated dashboard");
    db::replace_snapshot(&pool, &updated)
        .await
        .expect("upsert snapshot");
    assert_ingested_file(&pool, &updated.source_files[0], true).await;
    assert_observation_active(&pool, "event-000001-domain", false).await;
    assert_observation_active(&pool, "event-000002-domain", true).await;

    let domain_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE node_type = 'Domain' AND value = $1")
            .bind(domain(1))
            .fetch_one(&pool)
            .await
            .expect("count domain rows");
    assert_eq!(domain_rows, 1);
    assert_table_count_at_least(&pool, "node_history", 1).await;

    assert_transaction_rolls_back(&pool).await;
    assert_unique_node_constraint(&pool).await;
    assert_referential_integrity_constraint(&pool).await;

    db::replace_snapshot(
        &pool,
        &GraphSnapshot {
            nodes: Vec::new(),
            edges: Vec::new(),
            alerts: Vec::new(),
            fingerprint: "empty".to_string(),
            source_files: Vec::new(),
            observations: Vec::new(),
        },
    )
    .await
    .expect("delete stale graph rows");
    assert_table_count(&pool, "edges", 0).await;
    assert_table_count(&pool, "alerts", 0).await;
    assert_table_count(&pool, "nodes", 0).await;
    assert_table_count_at_least(&pool, "node_history", 1).await;
    assert_table_count_at_least(&pool, "alert_history", 1).await;
    assert_table_count_at_least(&pool, "edge_history", 1).await;
    assert_table_count_at_least(&pool, "ingested_files", 1).await;
    assert_ingested_file(&pool, &updated.source_files[0], false).await;
}

async fn assert_legacy_alert_identity_is_reconciled(pool: &sqlx::PgPool, snapshot: &GraphSnapshot) {
    let alert = &snapshot.alerts[0];
    let legacy_id = uuid("00000000-0000-0000-0000-00000000aa19");

    sqlx::query("UPDATE edges SET alert_id = NULL WHERE alert_id = $1")
        .bind(alert.id)
        .execute(pool)
        .await
        .expect("detach current alert identity");
    sqlx::query("UPDATE alerts SET id = $1 WHERE id = $2")
        .bind(legacy_id)
        .bind(alert.id)
        .execute(pool)
        .await
        .expect("replace alert with legacy identity");

    db::replace_snapshot(pool, snapshot)
        .await
        .expect("reconcile legacy alert identity");

    let stored_id: Uuid =
        sqlx::query_scalar("SELECT id FROM alerts WHERE source = $1 AND external_id = $2")
            .bind(&alert.source)
            .bind(&alert.external_id)
            .fetch_one(pool)
            .await
            .expect("load reconciled alert identity");
    assert_eq!(stored_id, alert.id);
}

async fn assert_ingested_file(
    pool: &sqlx::PgPool,
    expected: &ioc_graph_backend::models::IngestedFile,
    active: bool,
) {
    let stored: (String, i64, bool) = sqlx::query_as(
        "SELECT fingerprint, size_bytes, active FROM ingested_files WHERE path = $1",
    )
    .bind(&expected.path)
    .fetch_one(pool)
    .await
    .expect("load ingested file registry row");

    assert_eq!(stored.0, expected.fingerprint, "stored file fingerprint");
    assert_eq!(stored.1, expected.size_bytes, "stored file size");
    assert_eq!(stored.2, active, "stored file active state");
}

async fn assert_observation_active(pool: &sqlx::PgPool, record_id: &str, active: bool) {
    let stored: bool = sqlx::query_scalar(
        "SELECT active FROM observations WHERE source_record_id = $1 ORDER BY ingested_at DESC LIMIT 1",
    )
    .bind(record_id)
    .fetch_one(pool)
    .await
    .expect("load observation active state");
    assert_eq!(stored, active, "observation active state for {record_id}");
}

async fn assert_transaction_rolls_back(pool: &sqlx::PgPool) {
    let id = uuid("00000000-0000-0000-0000-00000000aaa1");
    let mut tx = pool.begin().await.expect("begin transaction");
    sqlx::query(
        r#"
        INSERT INTO nodes (id, node_type, value, label, first_seen, last_seen, metadata)
        VALUES ($1, 'Domain', 'rollback.example.test', 'rollback.example.test', now(), now(), '{}'::jsonb)
        "#,
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .expect("insert rollback node");
    tx.rollback().await.expect("rollback transaction");

    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nodes WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("check rolled back node");
    assert!(!exists);
}

async fn assert_unique_node_constraint(pool: &sqlx::PgPool) {
    let first = uuid("00000000-0000-0000-0000-00000000bbb1");
    let second = uuid("00000000-0000-0000-0000-00000000bbb2");
    let sql = r#"
        INSERT INTO nodes (id, node_type, value, label, first_seen, last_seen, metadata)
        VALUES ($1, 'Domain', 'unique.example.test', 'unique.example.test', now(), now(), '{}'::jsonb)
    "#;

    sqlx::query(sql)
        .bind(first)
        .execute(pool)
        .await
        .expect("insert first unique node");
    let duplicate = sqlx::query(sql).bind(second).execute(pool).await;

    assert!(duplicate.is_err(), "duplicate node_type + value must fail");
}

async fn assert_referential_integrity_constraint(pool: &sqlx::PgPool) {
    let invalid_node = uuid("00000000-0000-0000-0000-00000000ccc1");
    let edge_id = uuid("00000000-0000-0000-0000-00000000ccc2");
    let edge = sqlx::query(
        r#"
        INSERT INTO edges (
            id, source_node_id, target_node_id, relation, first_seen, last_seen, metadata
        )
        VALUES ($1, $2, $2, 'related_to', now(), now(), '{}'::jsonb)
        "#,
    )
    .bind(edge_id)
    .bind(invalid_node)
    .execute(pool)
    .await;

    assert!(edge.is_err(), "edge with missing nodes must fail");
}

async fn assert_table_count_at_least(pool: &sqlx::PgPool, table: &str, expected: i64) {
    let count = table_count(pool, table).await;
    assert!(
        count >= expected,
        "{table} should contain at least {expected} rows, got {count}"
    );
}

async fn assert_table_count(pool: &sqlx::PgPool, table: &str, expected: i64) {
    let count = table_count(pool, table).await;
    assert_eq!(count, expected, "{table} row count");
}

async fn table_count(pool: &sqlx::PgPool, table: &str) -> i64 {
    let sql = match table {
        "nodes" => "SELECT COUNT(*) FROM nodes",
        "edges" => "SELECT COUNT(*) FROM edges",
        "alerts" => "SELECT COUNT(*) FROM alerts",
        "ingested_files" => "SELECT COUNT(*) FROM ingested_files",
        "node_history" => "SELECT COUNT(*) FROM node_history",
        "alert_history" => "SELECT COUNT(*) FROM alert_history",
        "edge_history" => "SELECT COUNT(*) FROM edge_history",
        "observations" => "SELECT COUNT(*) FROM observations",
        _ => panic!("unexpected table name {table}"),
    };

    sqlx::query_scalar(sql)
        .fetch_one(pool)
        .await
        .expect("count table rows")
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("valid static uuid")
}

async fn assert_observation_constraints(pool: &sqlx::PgPool, source_file_path: &str) {
    sqlx::query(
        r#"
        INSERT INTO observations (
            source_file_path, source_record_id, content_fingerprint, payload
        ) VALUES ($1, 'record-1', 'version-1', '{"id":"record-1"}'::jsonb)
        "#,
    )
    .bind(source_file_path)
    .execute(pool)
    .await
    .expect("insert first observation version");

    let simultaneous_active_version = sqlx::query(
        r#"
        INSERT INTO observations (
            source_file_path, source_record_id, content_fingerprint, payload
        ) VALUES ($1, 'record-1', 'version-2', '{"id":"record-1"}'::jsonb)
        "#,
    )
    .bind(source_file_path)
    .execute(pool)
    .await;
    assert!(
        simultaneous_active_version.is_err(),
        "a source record must have only one active version"
    );

    sqlx::query(
        r#"
        UPDATE observations
        SET active = false, deactivated_at = now()
        WHERE source_file_path = $1 AND source_record_id = 'record-1' AND active
        "#,
    )
    .bind(source_file_path)
    .execute(pool)
    .await
    .expect("deactivate first observation version");

    sqlx::query(
        r#"
        INSERT INTO observations (
            source_file_path, source_record_id, content_fingerprint, payload
        ) VALUES ($1, 'record-1', 'version-2', '{"id":"record-1","version":2}'::jsonb)
        "#,
    )
    .bind(source_file_path)
    .execute(pool)
    .await
    .expect("insert replacement observation version");

    let versions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM observations WHERE source_file_path = $1 AND source_record_id = 'record-1'",
    )
    .bind(source_file_path)
    .fetch_one(pool)
    .await
    .expect("count observation versions");
    assert_eq!(versions, 2, "observation version count");
}
