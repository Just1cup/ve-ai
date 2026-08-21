mod common;

use ioc_graph_backend::ingest::load_dashboard_snapshot;

use common::{
    assert_no_duplicate_edges, assert_no_duplicate_nodes, domain, file, has_edge, hash, ip, mitre,
    node, record_with_context, DashboardFixture, SyntheticContext,
};

#[test]
fn correlates_ip_to_asn_country_and_provider_metadata() {
    let dashboard = DashboardFixture::new();
    let context = SyntheticContext::indexed(1)
        .source_ip("203.0.113.42")
        .asn("AS64500")
        .country("BR")
        .org("Example Telecom");
    dashboard.write_records(
        "iocs.json",
        &[record_with_context(1, "ip", "203.0.113.42", context)],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");
    let ip = node(&snapshot, "IP", "203.0.113.42");
    let asn = node(&snapshot, "ASN", "AS64500");
    let country = node(&snapshot, "Country", "BR");

    assert!(has_edge(&snapshot, ip.id, asn.id, "belongs_to"));
    assert!(has_edge(&snapshot, ip.id, country.id, "belongs_to"));
    assert_eq!(asn.description.as_deref(), Some("Example Telecom"));
    assert_eq!(asn.metadata["org"], "Example Telecom");
}

#[test]
fn correlates_domain_to_resolved_ip() {
    let dashboard = DashboardFixture::new();
    let context = SyntheticContext::indexed(2).source_ip("198.51.100.77");
    dashboard.write_records(
        "iocs.json",
        &[record_with_context(
            2,
            "domain",
            "resolver.example.test",
            context,
        )],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");
    let domain = node(&snapshot, "Domain", "resolver.example.test");
    let ip = node(&snapshot, "IP", "198.51.100.77");

    assert!(has_edge(&snapshot, domain.id, ip.id, "resolves_to"));
}

#[test]
fn correlates_url_under_owning_domain() {
    let dashboard = DashboardFixture::new();
    let url = "https://download.example.test/payload.exe";
    dashboard.write_records(
        "iocs.json",
        &[record_with_context(
            3,
            "url",
            url,
            SyntheticContext::indexed(3),
        )],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");
    let domain = node(&snapshot, "Domain", "download.example.test");
    let url = node(&snapshot, "URL", url);

    assert!(has_edge(&snapshot, domain.id, url.id, "hosts"));
}

#[test]
fn correlates_file_and_hash_as_shared_entities() {
    let dashboard = DashboardFixture::new();
    let shared_file = "shared-payload.exe";
    let shared_hash = hash(4);
    let file_context = SyntheticContext::indexed(4)
        .file(shared_file)
        .hash(shared_hash.clone())
        .alert_id("file-hash-alert");
    let hash_context = SyntheticContext::indexed(5)
        .file(shared_file)
        .hash(shared_hash.clone())
        .alert_id("file-hash-alert");

    dashboard.write_records(
        "iocs.json",
        &[
            record_with_context(4, "file", shared_file, file_context),
            record_with_context(5, "hash", shared_hash.clone(), hash_context),
        ],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");
    let file = node(&snapshot, "File", shared_file);
    let hash = node(&snapshot, "Hash", &shared_hash);

    assert!(has_edge(&snapshot, hash.id, file.id, "related_to"));
    assert_eq!(
        snapshot
            .nodes
            .iter()
            .filter(|node| node.node_type == "File" && node.value == shared_file)
            .count(),
        1
    );
    assert_eq!(
        snapshot
            .nodes
            .iter()
            .filter(|node| node.node_type == "Hash" && node.value == shared_hash)
            .count(),
        1
    );
}

#[test]
fn correlates_url_to_file_through_shared_hash_context() {
    let dashboard = DashboardFixture::new();
    let url_value = "https://files.example.test/dropper.exe";
    let file_value = "dropper.exe";
    let hash_value = hash(6);
    let context = SyntheticContext::indexed(6)
        .file(file_value)
        .hash(hash_value.clone())
        .alert_id("url-file-alert");

    dashboard.write_records(
        "iocs.json",
        &[record_with_context(6, "url", url_value, context)],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");
    let url = node(&snapshot, "URL", url_value);
    let hash = node(&snapshot, "Hash", &hash_value);
    let file = node(&snapshot, "File", file_value);

    assert!(has_edge(&snapshot, url.id, hash.id, "related_to"));
    assert!(has_edge(&snapshot, hash.id, file.id, "related_to"));
}

#[test]
fn correlates_ioc_to_alert_and_mitre_technique() {
    let dashboard = DashboardFixture::new();
    let context = SyntheticContext::indexed(7)
        .mitre("T1105", "Ingress Tool Transfer")
        .alert_id("mitre-alert");
    dashboard.write_records(
        "iocs.json",
        &[record_with_context(7, "domain", domain(7), context.clone())],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");
    let domain = node(&snapshot, "Domain", &domain(7));
    let alert = node(
        &snapshot,
        "Alert",
        &format!("{}:{}", context.source, context.alert_id),
    );
    let technique = node(&snapshot, "MITRE Technique", "T1105");

    assert!(has_edge(&snapshot, domain.id, alert.id, "seen_in"));
    assert!(has_edge(&snapshot, domain.id, technique.id, "mapped_to"));
    assert!(has_edge(&snapshot, alert.id, technique.id, "mapped_to"));
}

#[test]
fn shared_relationships_are_represented_once_and_reused() {
    let dashboard = DashboardFixture::new();
    let shared_asn = "AS13335";
    let ip_a = ip(21);
    let ip_b = ip(22);
    let domain_a = domain(21);
    let domain_b = domain(22);
    let context_a = SyntheticContext::indexed(21)
        .source_ip(ip_a.clone())
        .asn(shared_asn)
        .org("Cloud Edge Network")
        .alert_id("asn-shared-a");
    let context_b = SyntheticContext::indexed(22)
        .source_ip(ip_b.clone())
        .asn(shared_asn)
        .org("Cloud Edge Network")
        .alert_id("asn-shared-b");

    dashboard.write_records(
        "iocs.json",
        &[
            record_with_context(21, "domain", domain_a.clone(), context_a),
            record_with_context(22, "domain", domain_b.clone(), context_b),
        ],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");
    assert_no_duplicate_nodes(&snapshot);
    assert_no_duplicate_edges(&snapshot);

    let asn = node(&snapshot, "ASN", shared_asn);
    let ip_a = node(&snapshot, "IP", &ip_a);
    let ip_b = node(&snapshot, "IP", &ip_b);
    let domain_a = node(&snapshot, "Domain", &domain_a);
    let domain_b = node(&snapshot, "Domain", &domain_b);

    assert!(has_edge(&snapshot, ip_a.id, asn.id, "belongs_to"));
    assert!(has_edge(&snapshot, ip_b.id, asn.id, "belongs_to"));
    assert!(has_edge(&snapshot, domain_a.id, ip_a.id, "resolves_to"));
    assert!(has_edge(&snapshot, domain_b.id, ip_b.id, "resolves_to"));
    assert_eq!(
        snapshot
            .nodes
            .iter()
            .filter(|node| node.node_type == "ASN" && node.value == shared_asn)
            .count(),
        1
    );
}

#[test]
fn many_alerts_referencing_same_ioc_reuse_same_entity() {
    let dashboard = DashboardFixture::new();
    let repeated = "reused.example.test";
    dashboard.write_records(
        "iocs.json",
        &[
            record_with_context(30, "domain", repeated, SyntheticContext::indexed(30)),
            record_with_context(31, "domain", repeated, SyntheticContext::indexed(31)),
            record_with_context(32, "domain", repeated, SyntheticContext::indexed(32)),
        ],
    );

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");

    assert_eq!(
        snapshot
            .nodes
            .iter()
            .filter(|node| node.node_type == "Domain" && node.value == repeated)
            .count(),
        1
    );
    assert_eq!(snapshot.alerts.len(), 3);
}

#[test]
fn synthetic_generators_create_expected_ioc_types() {
    assert!(ip(1).starts_with("198.51.100."));
    assert!(domain(1).ends_with(".example.test"));
    assert!(file(1).ends_with(".exe"));
    assert_eq!(hash(1).len(), 64);
    assert!(mitre(1).starts_with('T'));
}
