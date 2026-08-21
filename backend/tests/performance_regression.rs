mod common;

use std::{
    collections::HashMap,
    env, fs,
    time::{Duration, Instant},
};

use ioc_graph_backend::ingest::load_dashboard_snapshot;
use serde_json::Value;

use common::{record, records, DashboardFixture};

#[test]
fn graph_build_time_regression_guard() {
    let Some(baseline) = baseline() else {
        return;
    };
    let dashboard = DashboardFixture::new();
    dashboard.write_records("iocs.json", &records(2_000));

    let elapsed = elapsed(|| {
        let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load snapshot");
        assert!(!snapshot.nodes.is_empty());
    });

    assert_elapsed_within("graph_build_ms", elapsed, &baseline, 1.15);
}

#[test]
fn memory_growth_regression_guard() {
    let Some(baseline) = baseline() else {
        return;
    };
    let Some(before) = rss_bytes() else {
        return;
    };

    let dashboard = DashboardFixture::new();
    dashboard.write_records("iocs.json", &records(5_000));
    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load snapshot");
    assert!(!snapshot.nodes.is_empty());

    let Some(after) = rss_bytes() else {
        return;
    };
    let growth = after.saturating_sub(before);
    assert_value_within("memory_growth_bytes", growth as f64, &baseline, 1.20);
}

#[test]
fn single_change_update_speed_regression_guard() {
    let Some(baseline) = baseline() else {
        return;
    };
    let dashboard = DashboardFixture::new();
    let mut data = records(2_000);
    dashboard.write_records("iocs.json", &data);
    let initial = load_dashboard_snapshot(dashboard.path()).expect("load initial snapshot");

    data[100] = record(100, "domain", "changed-regression.example.test");
    dashboard.write_records("iocs.json", &data);
    let elapsed = elapsed(|| {
        let updated = load_dashboard_snapshot(dashboard.path()).expect("load changed snapshot");
        assert_ne!(initial.fingerprint, updated.fingerprint);
    });

    assert_elapsed_within("single_change_update_ms", elapsed, &baseline, 1.25);
}

#[test]
fn indexed_query_speed_regression_guard() {
    let Some(baseline) = baseline() else {
        return;
    };
    let entities = search_entities(100_000);
    let index: HashMap<_, _> = entities
        .iter()
        .enumerate()
        .map(|(position, (node_type, value))| (format!("{node_type}\u{1f}{value}"), position))
        .collect();
    let keys = [
        "IP\u{1f}198.51.100.1".to_string(),
        "Domain\u{1f}query-1.example.test".to_string(),
        "Hash\u{1f}0000000000000000000000000000000000000000000000000000000000000002".to_string(),
        "ASN\u{1f}AS13338".to_string(),
    ];

    let elapsed = elapsed(|| {
        for _ in 0..1_000 {
            for key in &keys {
                assert!(index.get(key).is_some());
            }
        }
    });

    assert_elapsed_within("indexed_query_ms", elapsed, &baseline, 1.25);
}

#[test]
#[ignore = "large load test: generates 100k synthetic IOCs and should be run explicitly"]
fn load_test_100k_iocs_remains_bounded_and_completes() {
    let dashboard = DashboardFixture::new();
    dashboard.write_records("iocs.json", &records(100_000));

    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load 100k snapshot");

    assert!(snapshot.nodes.len() >= 100_000);
    assert!(snapshot.edges.len() >= 500_000);
    assert_eq!(snapshot.alerts.len(), 100_000);
}

fn baseline() -> Option<Value> {
    let path = env::var("IOC_GRAPH_PERF_BASELINE").ok()?;
    let raw = fs::read_to_string(path).expect("read performance baseline json");
    Some(serde_json::from_str(&raw).expect("parse performance baseline json"))
}

fn elapsed(work: impl FnOnce()) -> Duration {
    let start = Instant::now();
    work();
    start.elapsed()
}

fn assert_elapsed_within(key: &str, elapsed: Duration, baseline: &Value, max_ratio: f64) {
    assert_value_within(key, elapsed.as_secs_f64() * 1_000.0, baseline, max_ratio);
}

fn assert_value_within(key: &str, current: f64, baseline: &Value, max_ratio: f64) {
    let expected = baseline
        .get(key)
        .and_then(Value::as_f64)
        .unwrap_or_else(|| panic!("missing performance baseline key {key}"));
    let max = expected * max_ratio;
    assert!(
        current <= max,
        "{key} regression: current={current:.3}, baseline={expected:.3}, allowed={max:.3}"
    );
}

fn rss_bytes() -> Option<u64> {
    let statm = fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(resident_pages * 4096)
}

fn search_entities(count: usize) -> Vec<(String, String)> {
    (0..count)
        .map(|index| match index % 4 {
            0 => (
                "IP".to_string(),
                format!("198.51.100.{}", (index % 250) + 1),
            ),
            1 => ("Domain".to_string(), format!("query-{index}.example.test")),
            2 => ("Hash".to_string(), format!("{index:064x}")),
            _ => ("ASN".to_string(), format!("AS{}", 13335 + (index % 64))),
        })
        .collect()
}
