mod support;

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use support::{topology_levels, GRAPH_SIZES};

fn bench_layout_topology(c: &mut Criterion) {
    let mut group = c.benchmark_group("layout_topology_levels");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &size in GRAPH_SIZES {
        let records = support::records(size);
        let snapshot = support::load_snapshot(&records);
        group.throughput(Throughput::Elements(snapshot.nodes.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &snapshot,
            |b, snapshot| {
                b.iter(|| {
                    let levels = topology_levels(std::hint::black_box(snapshot));
                    std::hint::black_box(levels.len())
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_layout_topology);
criterion_main!(benches);
