mod common;

use chrono::{DateTime, Utc};
use ioc_graph_backend::ingest::load_dashboard_snapshot;

use common::{
    assert_edges_reference_existing_nodes, assert_no_duplicate_edges, assert_no_duplicate_nodes,
    domain, edges, find_node, ip, node, record, record_with_context, DashboardFixture,
    SyntheticContext,
};

#[test]
fn creates_ioc_alert_and_source_nodes() {
    let dashboard = DashboardFixture::new();
    let context = SyntheticContext::indexed(1);
    dashboard.write_records(
        "iocs.json",
        &[record_with_context(1, "ip", ip(1), context.clone())],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");

    assert_eq!(node(&snapshot, "IP", &ip(1)).value, ip(1));
    assert_eq!(
        node(
            &snapshot,
            "Alert",
            &format!("{}:{}", context.source, context.alert_id)
        )
        .source,
        Some(context.source.clone())
    );
    assert_eq!(
        node(&snapshot, "Source", &context.source).value,
        context.source
    );
    assert_eq!(
        node(&snapshot, "Source", &context.source).label,
        context.region
    );
    assert_eq!(
        node(&snapshot, "IP", &ip(1)).metadata["region"].as_str(),
        Some(context.region.as_str())
    );
}

#[test]
fn creates_seen_in_edges_between_ioc_alert_and_source() {
    let dashboard = DashboardFixture::new();
    let context = SyntheticContext::indexed(2);
    dashboard.write_records(
        "iocs.json",
        &[record_with_context(2, "domain", domain(2), context.clone())],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");
    let domain = node(&snapshot, "Domain", &domain(2));
    let alert = node(
        &snapshot,
        "Alert",
        &format!("{}:{}", context.source, context.alert_id),
    );
    let source = node(&snapshot, "Source", &context.source);

    assert_eq!(edges(&snapshot, domain.id, alert.id, "seen_in").len(), 1);
    assert_eq!(edges(&snapshot, domain.id, source.id, "seen_in").len(), 1);
    assert_eq!(edges(&snapshot, source.id, alert.id, "seen_in").len(), 1);
}

#[test]
fn deduplicates_nodes_edges_and_reuses_shared_entities() {
    let dashboard = DashboardFixture::new();
    let shared_ip = "203.0.113.10";
    let shared_asn = "AS13335";
    let shared_source = "dashboard:shared";
    let context_a = SyntheticContext::indexed(10)
        .source(shared_source)
        .source_ip(shared_ip)
        .asn(shared_asn)
        .org("Example Shared Network")
        .alert_id("shared-a");
    let context_b = SyntheticContext::indexed(11)
        .source(shared_source)
        .source_ip(shared_ip)
        .asn(shared_asn)
        .org("Example Shared Network")
        .alert_id("shared-b");

    dashboard.write_records(
        "iocs.json",
        &[
            record_with_context(10, "domain", "domain-a.example.test", context_a),
            record_with_context(11, "domain", "domain-b.example.test", context_b),
            record_with_context(
                12,
                "domain",
                "domain-a.example.test",
                SyntheticContext::indexed(10),
            ),
        ],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");
    assert_no_duplicate_nodes(&snapshot);
    assert_no_duplicate_edges(&snapshot);

    assert_eq!(
        snapshot
            .nodes
            .iter()
            .filter(|node| node.node_type == "IP" && node.value == shared_ip)
            .count(),
        1
    );
    assert_eq!(
        snapshot
            .nodes
            .iter()
            .filter(|node| node.node_type == "ASN" && node.value == shared_asn)
            .count(),
        1
    );

    let ip_node = node(&snapshot, "IP", shared_ip);
    let asn_node = node(&snapshot, "ASN", shared_asn);
    assert_eq!(
        edges(&snapshot, ip_node.id, asn_node.id, "belongs_to").len(),
        1
    );
}

#[test]
fn merges_first_seen_and_last_seen_for_repeated_entities() {
    let dashboard = DashboardFixture::new();
    let value = "timeline.example.test";
    let early = SyntheticContext::indexed(20)
        .first_seen("2026-01-01T00:00:00Z")
        .last_seen("2026-01-01T00:05:00Z")
        .alert_id("timeline-a");
    let late = SyntheticContext::indexed(21)
        .first_seen("2026-01-03T00:00:00Z")
        .last_seen("2026-01-03T00:30:00Z")
        .alert_id("timeline-b");

    dashboard.write_records(
        "iocs.json",
        &[
            record_with_context(20, "domain", value, late),
            record_with_context(21, "domain", value, early),
        ],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");
    let domain = node(&snapshot, "Domain", value);

    assert_eq!(domain.first_seen, parse_time("2026-01-01T00:00:00Z"));
    assert_eq!(domain.last_seen, parse_time("2026-01-03T00:30:00Z"));
}

#[test]
fn changed_snapshot_removes_absent_entities_from_graph_model() {
    let dashboard = DashboardFixture::new();
    dashboard.write_records(
        "iocs.json",
        &[
            record(30, "domain", domain(30)),
            record(31, "domain", domain(31)),
        ],
    );
    let initial = load_dashboard_snapshot(dashboard.path()).expect("load initial dashboard");

    dashboard.write_records("iocs.json", &[record(30, "domain", domain(30))]);
    let updated = load_dashboard_snapshot(dashboard.path()).expect("load updated dashboard");

    assert_ne!(initial.fingerprint, updated.fingerprint);
    assert!(find_node(&updated, "Domain", &domain(30)).is_some());
    assert!(find_node(&updated, "Domain", &domain(31)).is_none());
}

#[test]
fn updated_entity_keeps_stable_identity() {
    let dashboard = DashboardFixture::new();
    let value = "stable.example.test";
    dashboard.write_records(
        "iocs.json",
        &[record_with_context(
            40,
            "domain",
            value,
            SyntheticContext::indexed(40)
                .first_seen("2026-01-01T00:00:00Z")
                .last_seen("2026-01-01T00:10:00Z"),
        )],
    );
    let initial = load_dashboard_snapshot(dashboard.path()).expect("load initial dashboard");
    let initial_node = node(&initial, "Domain", value);

    dashboard.write_records(
        "iocs.json",
        &[record_with_context(
            41,
            "domain",
            value,
            SyntheticContext::indexed(41)
                .first_seen("2026-01-01T00:00:00Z")
                .last_seen("2026-01-01T00:40:00Z"),
        )],
    );
    let updated = load_dashboard_snapshot(dashboard.path()).expect("load updated dashboard");
    let updated_node = node(&updated, "Domain", value);

    assert_eq!(initial_node.id, updated_node.id);
    assert_eq!(updated_node.last_seen, parse_time("2026-01-01T00:40:00Z"));
}

#[test]
fn graph_edges_always_reference_existing_nodes() {
    let dashboard = DashboardFixture::new();
    dashboard.write_records(
        "iocs.json",
        &[record(50, "url", "https://links.example.test/a")],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");

    assert_edges_reference_existing_nodes(&snapshot);
    assert_no_duplicate_nodes(&snapshot);
    assert_no_duplicate_edges(&snapshot);
}

fn parse_time(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("valid rfc3339")
        .with_timezone(&Utc)
}
