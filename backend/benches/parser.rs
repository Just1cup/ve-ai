mod support;

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ioc_graph_backend::ingest::load_dashboard_snapshot;

use support::{BenchDashboard, PARSER_BYTES};

fn bench_parser(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &bytes in PARSER_BYTES {
        let dashboard = BenchDashboard::with_json_bytes(bytes);
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_with_input(
            BenchmarkId::new("dashboard_json_bytes", bytes),
            dashboard.path(),
            |b, path| {
                b.iter(|| {
                    let snapshot =
                        load_dashboard_snapshot(std::hint::black_box(path)).expect("parse payload");
                    std::hint::black_box(snapshot.nodes.len())
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_parser);
criterion_main!(benches);
