mod support;

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ioc_graph_backend::ingest::load_dashboard_snapshot;

use support::{rss_bytes, BenchDashboard, MEMORY_SIZES};

fn bench_memory_growth(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_graph_snapshot");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &size in MEMORY_SIZES {
        let records = support::records(size);
        let dashboard = BenchDashboard::with_records(&records);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            dashboard.path(),
            |b, path| {
                b.iter(|| {
                    let before = rss_bytes();
                    let snapshot =
                        load_dashboard_snapshot(std::hint::black_box(path)).expect("load snapshot");
                    let after = rss_bytes();
                    let bytes_per_node = after
                        .zip(Some(snapshot.nodes.len() as u64))
                        .and_then(|(rss, nodes)| (nodes > 0).then_some(rss / nodes));
                    let bytes_per_edge = after
                        .zip(Some(snapshot.edges.len() as u64))
                        .and_then(|(rss, edges)| (edges > 0).then_some(rss / edges));

                    std::hint::black_box((
                        before,
                        after,
                        bytes_per_node,
                        bytes_per_edge,
                        snapshot.nodes.len(),
                        snapshot.edges.len(),
                    ))
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_memory_growth);
criterion_main!(benches);
