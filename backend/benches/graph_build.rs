mod support;

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ioc_graph_backend::ingest::load_dashboard_snapshot;

use support::{BenchDashboard, GRAPH_SIZES};

fn bench_graph_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph_build");
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
                    std::hint::black_box((
                        snapshot.nodes.len(),
                        snapshot.edges.len(),
                        snapshot.alerts.len(),
                    ))
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_graph_build);
criterion_main!(benches);
