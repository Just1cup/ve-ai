mod support;

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ioc_graph_backend::ingest::load_dashboard_snapshot;

use support::{BenchDashboard, GRAPH_SIZES};

fn bench_correlation(c: &mut Criterion) {
    relation_creation(c);
    relation_update_and_removal(c);
    deduplication(c);
}

fn relation_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_relation_creation");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &size in GRAPH_SIZES {
        let records = support::records(size);
        let dashboard = BenchDashboard::with_records(&records);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            dashboard.path(),
            |b, path| {
                b.iter(|| {
                    let snapshot =
                        load_dashboard_snapshot(std::hint::black_box(path)).expect("load snapshot");
                    std::hint::black_box((snapshot.nodes.len(), snapshot.edges.len()))
                });
            },
        );
    }

    group.finish();
}

fn relation_update_and_removal(c: &mut Criterion) {
    let size = 10_000;
    let mut base = support::records(size);
    let base_dashboard = BenchDashboard::with_records(&base);

    base[17] = support::record(17, "domain", "changed-single-correlation.example.test");
    let changed_dashboard = BenchDashboard::with_records(&base);

    let removed_dashboard = BenchDashboard::with_records(&base[..size - 1_000]);

    let mut group = c.benchmark_group("correlation_update_remove");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));
    group.throughput(Throughput::Elements(size as u64));

    group.bench_function("full_rebuild_10000", |b| {
        b.iter(|| {
            let snapshot = load_dashboard_snapshot(std::hint::black_box(base_dashboard.path()))
                .expect("load snapshot");
            std::hint::black_box(snapshot.fingerprint)
        });
    });
    group.bench_function("single_ioc_changed_rebuild_10000", |b| {
        b.iter(|| {
            let snapshot = load_dashboard_snapshot(std::hint::black_box(changed_dashboard.path()))
                .expect("load changed snapshot");
            std::hint::black_box(snapshot.fingerprint)
        });
    });
    group.bench_function("removed_relations_rebuild_9000", |b| {
        b.iter(|| {
            let snapshot = load_dashboard_snapshot(std::hint::black_box(removed_dashboard.path()))
                .expect("load reduced snapshot");
            std::hint::black_box(snapshot.fingerprint)
        });
    });

    group.finish();
}

fn deduplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_deduplication");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &unique_count in &[100, 1_000, 10_000] {
        let records = support::duplicate_domain_records(unique_count, 10);
        let dashboard = BenchDashboard::with_records(&records);
        let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dedup snapshot");
        support::assert_deduplicated(&snapshot);

        group.throughput(Throughput::Elements(records.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("repeated_iocs", records.len()),
            dashboard.path(),
            |b, path| {
                b.iter(|| {
                    let snapshot = load_dashboard_snapshot(std::hint::black_box(path))
                        .expect("load dedup snapshot");
                    std::hint::black_box((snapshot.nodes.len(), snapshot.edges.len()))
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_correlation);
criterion_main!(benches);
