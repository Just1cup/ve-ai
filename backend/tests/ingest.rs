mod common;

use std::collections::HashMap;

use ioc_graph_backend::ingest::load_dashboard_snapshot;

use common::{
    domain, find_node, ip, node, record_with_context, records, DashboardFixture, SyntheticContext,
};

#[test]
fn identical_dashboard_content_has_stable_fingerprint() {
    let dashboard = DashboardFixture::new();
    dashboard.write_records("iocs.json", &records(100));

    let first = load_dashboard_snapshot(dashboard.path()).expect("load first snapshot");
    let second = load_dashboard_snapshot(dashboard.path()).expect("load second snapshot");

    assert_eq!(first.fingerprint, second.fingerprint);
    assert_eq!(first.nodes.len(), second.nodes.len());
    assert_eq!(first.edges.len(), second.edges.len());
    assert_eq!(first.alerts.len(), second.alerts.len());
}

#[test]
fn changed_dashboard_content_changes_fingerprint() {
    let dashboard = DashboardFixture::new();
    dashboard.write_records("iocs.json", &records(20));
    let first = load_dashboard_snapshot(dashboard.path()).expect("load first snapshot");

    let mut changed = records(20);
    changed.push(record_with_context(
        21,
        "domain",
        "new-fingerprint.example.test",
        SyntheticContext::indexed(21),
    ));
    dashboard.write_records("iocs.json", &changed);
    let second = load_dashboard_snapshot(dashboard.path()).expect("load second snapshot");

    assert_ne!(first.fingerprint, second.fingerprint);
    assert_eq!(second.alerts.len(), first.alerts.len() + 1);
}

#[test]
fn single_ioc_change_preserves_unaffected_node_identities() {
    let dashboard = DashboardFixture::new();
    let initial_records: Vec<_> = (0..40)
        .map(|index| {
            record_with_context(
                index,
                "domain",
                domain(index),
                SyntheticContext::indexed(index)
                    .source_ip(ip(index + 1_000))
                    .alert_id(format!("incremental-{index:03}")),
            )
        })
        .collect();
    dashboard.write_records("iocs.json", &initial_records);
    let initial = load_dashboard_snapshot(dashboard.path()).expect("load initial snapshot");
    let initial_domain_ids = domain_ids(&initial);

    let mut updated_records = initial_records;
    updated_records[17] = record_with_context(
        17,
        "domain",
        "changed-only-one.example.test",
        SyntheticContext::indexed(17)
            .source_ip(ip(17 + 1_000))
            .alert_id("incremental-017"),
    );
    dashboard.write_records("iocs.json", &updated_records);
    let updated = load_dashboard_snapshot(dashboard.path()).expect("load updated snapshot");
    let updated_domain_ids = domain_ids(&updated);

    for index in 0..40 {
        if index == 17 {
            continue;
        }
        let value = domain(index);
        assert_eq!(
            initial_domain_ids.get(&value),
            updated_domain_ids.get(&value),
            "unchanged domain identity should stay stable for {value}"
        );
    }
    assert!(find_node(&updated, "Domain", &domain(17)).is_none());
    assert!(find_node(&updated, "Domain", "changed-only-one.example.test").is_some());
}

#[test]
fn successive_updates_do_not_accumulate_stale_snapshot_entities() {
    let dashboard = DashboardFixture::new();
    let mut previous_node_count = 0;

    for round in 0..6 {
        let records: Vec<_> = (0..50)
            .map(|index| {
                record_with_context(
                    index,
                    "domain",
                    format!("round-{round}-{}.example.test", index % 10),
                    SyntheticContext::indexed(index)
                        .source_ip(format!("203.0.113.{}", index + 1))
                        .alert_id(format!("round-{round}-alert-{index:03}")),
                )
            })
            .collect();
        dashboard.write_records("iocs.json", &records);
        let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load snapshot");

        if previous_node_count != 0 {
            assert!(
                snapshot.nodes.len() <= previous_node_count + 60,
                "snapshot node count grew unexpectedly: previous={previous_node_count}, current={}",
                snapshot.nodes.len()
            );
        }
        previous_node_count = snapshot.nodes.len();
    }
}

#[test]
fn changed_context_reuses_ioc_node_but_updates_related_entities() {
    let dashboard = DashboardFixture::new();
    let value = "context-change.example.test";
    dashboard.write_records(
        "iocs.json",
        &[record_with_context(
            70,
            "domain",
            value,
            SyntheticContext::indexed(70)
                .source_ip("198.51.100.70")
                .asn("AS64570")
                .alert_id("context-change"),
        )],
    );
    let initial = load_dashboard_snapshot(dashboard.path()).expect("load initial snapshot");
    let initial_domain = node(&initial, "Domain", value);

    dashboard.write_records(
        "iocs.json",
        &[record_with_context(
            70,
            "domain",
            value,
            SyntheticContext::indexed(70)
                .source_ip("198.51.100.71")
                .asn("AS64571")
                .alert_id("context-change"),
        )],
    );
    let updated = load_dashboard_snapshot(dashboard.path()).expect("load updated snapshot");
    let updated_domain = node(&updated, "Domain", value);

    assert_eq!(initial_domain.id, updated_domain.id);
    assert!(find_node(&updated, "IP", "198.51.100.70").is_none());
    assert!(find_node(&updated, "IP", "198.51.100.71").is_some());
    assert!(find_node(&updated, "ASN", "AS64570").is_none());
    assert!(find_node(&updated, "ASN", "AS64571").is_some());
}

fn domain_ids(snapshot: &ioc_graph_backend::models::GraphSnapshot) -> HashMap<String, uuid::Uuid> {
    snapshot
        .nodes
        .iter()
        .filter(|node| node.node_type == "Domain")
        .map(|node| (node.value.clone(), node.id))
        .collect()
}
