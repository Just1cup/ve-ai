mod common;

use ioc_graph_backend::ingest::load_dashboard_snapshot;
use serde_json::json;

use common::{domain, record, records, DashboardFixture};

#[test]
fn parses_valid_json_records() {
    let dashboard = DashboardFixture::new();
    dashboard.write_records("iocs.json", &[record(1, "domain", domain(1))]);

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load valid dashboard");

    assert!(snapshot.nodes.iter().any(|node| node.node_type == "Domain"));
    assert!(!snapshot.edges.is_empty());
    assert_eq!(snapshot.alerts.len(), 1);
}

#[test]
fn parses_supported_email_and_cve_records() {
    let dashboard = DashboardFixture::new();
    dashboard.write_records(
        "iocs-000001.json",
        &[
            record(1, "email", "Analyst@Example.COM"),
            record(2, "cve", "cve-2026-12345"),
        ],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load IOC shard");

    assert!(snapshot
        .nodes
        .iter()
        .any(|node| node.node_type == "Email" && node.value == "analyst@example.com"));
    assert!(snapshot
        .nodes
        .iter()
        .any(|node| node.node_type == "CVE" && node.value == "CVE-2026-12345"));
    assert_eq!(snapshot.alerts.len(), 2);
}

#[test]
fn manifest_selects_only_active_ioc_shards() {
    let dashboard = DashboardFixture::new();
    dashboard.write_records(
        "data/iocs-old-generation-000001.json",
        &[record(1, "domain", "old.example.test")],
    );
    dashboard.write_records(
        "data/iocs-new-generation-000001.json",
        &[record(2, "domain", "active.example.test")],
    );
    dashboard.write_raw(
        "data/iocs-manifest.json",
        br#"{"version":1,"files":["iocs-new-generation-000001.json"]}"#,
    );

    let snapshot =
        load_dashboard_snapshot(dashboard.path()).expect("load active IOC shard generation");

    assert!(snapshot
        .nodes
        .iter()
        .any(|node| node.value == "active.example.test"));
    assert!(!snapshot
        .nodes
        .iter()
        .any(|node| node.value == "old.example.test"));
}

#[test]
fn manifest_rejects_unsafe_shard_paths() {
    let dashboard = DashboardFixture::new();
    dashboard.write_raw(
        "data/iocs-manifest.json",
        br#"{"version":1,"files":["../iocs-escape-000001.json"]}"#,
    );

    let error = load_dashboard_snapshot(dashboard.path()).expect_err("unsafe shard path must fail");

    assert!(error.to_string().contains("invalid IOC shard name"));
}

#[test]
fn returns_error_for_invalid_json_file() {
    let dashboard = DashboardFixture::new();
    dashboard.write_raw("broken.json", br#"[{"type":"ip","value":"198.51.100.10"}"#);

    let error = load_dashboard_snapshot(dashboard.path()).expect_err("invalid json must fail");

    assert!(error.to_string().contains("failed to read dashboard json"));
}

#[test]
fn returns_error_for_empty_json_file() {
    let dashboard = DashboardFixture::new();
    dashboard.write_raw("empty.json", b"");

    assert!(load_dashboard_snapshot(dashboard.path()).is_err());
}

#[test]
fn ignores_records_with_missing_required_fields() {
    let dashboard = DashboardFixture::new();
    dashboard.write_records(
        "missing-fields.json",
        &[
            json!({ "type": "domain" }),
            json!({ "value": "missing-type.example.test" }),
            json!({ "type": "", "value": "" }),
        ],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");

    assert!(snapshot.nodes.is_empty());
    assert!(snapshot.edges.is_empty());
    assert!(snapshot.alerts.is_empty());
}

#[test]
fn skips_records_with_incorrect_field_types() {
    let dashboard = DashboardFixture::new();
    dashboard.write_records(
        "wrong-types.json",
        &[
            json!({ "type": 42, "value": "198.51.100.42" }),
            json!({ "type": "ip", "value": ["198.51.100.43"] }),
        ],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");

    assert!(snapshot.nodes.is_empty());
}

#[test]
fn preserves_utf8_and_unicode_values() {
    let dashboard = DashboardFixture::new();
    dashboard.write_records(
        "unicode.json",
        &[record(7, "domain", "exemplo-ação.example.test")],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load unicode dashboard");

    assert!(snapshot
        .nodes
        .iter()
        .any(|node| node.node_type == "Domain" && node.value == "exemplo-ação.example.test"));
}

#[test]
fn sanitizes_lone_surrogate_escapes_in_dashboard_json() {
    let dashboard = DashboardFixture::new();
    dashboard.write_raw(
        "surrogate.json",
        br#"[{"type":"domain","value":"surrogate.example.test","description":"bad \ud83d"}]"#,
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load sanitized dashboard");

    assert!(snapshot
        .nodes
        .iter()
        .any(|node| node.node_type == "Domain" && node.value == "surrogate.example.test"));
}

#[test]
fn parses_large_synthetic_file_without_external_fixtures() {
    let dashboard = DashboardFixture::new();
    dashboard.write_records("large.json", &records(5_000));

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load large dashboard");

    assert!(snapshot.nodes.len() >= 5_000);
    assert!(snapshot.edges.len() >= 5_000);
    assert_eq!(snapshot.alerts.len(), 5_000);
}
