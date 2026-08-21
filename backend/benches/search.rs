mod support;

use std::{collections::HashMap, time::Duration};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ioc_graph_backend::models::GraphNode;

use support::SEARCH_SIZES;

fn bench_search(c: &mut Criterion) {
    exact_lookup_by_type(c);
    generic_ioc_scan(c);
}

fn exact_lookup_by_type(c: &mut Criterion) {
    let mut group = c.benchmark_group("search_exact_indexed");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &size in SEARCH_SIZES {
        let entities = support::search_entities(size);
        let index = exact_index(&entities);
        let keys = [
            key("IP", &support::ip(0)),
            key("Domain", &support::domain(1)),
            key("Hash", &support::hash(2)),
            key("ASN", &support::asn(3)),
            key("URL", &support::url(4)),
        ];

        group.throughput(Throughput::Elements(size as u64));
        for search_key in keys {
            group.bench_with_input(
                BenchmarkId::new(search_key.split('\u{1f}').next().unwrap(), size),
                &search_key,
                |b, search_key| {
                    b.iter(|| {
                        let result = index.get(std::hint::black_box(search_key));
                        std::hint::black_box(result)
                    });
                },
            );
        }
    }

    group.finish();
}

fn generic_ioc_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("search_generic_ioc_scan");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &size in SEARCH_SIZES {
        let entities = support::search_entities(size);
        let needle = "bench-999";

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &entities,
            |b, entities| {
                b.iter(|| {
                    let result = entities
                        .iter()
                        .filter(|node| node.value.contains(std::hint::black_box(needle)))
                        .count();
                    std::hint::black_box(result)
                });
            },
        );
    }

    group.finish();
}

fn exact_index(entities: &[GraphNode]) -> HashMap<String, usize> {
    entities
        .iter()
        .enumerate()
        .map(|(index, node)| (key(&node.node_type, &node.value), index))
        .collect()
}

fn key(node_type: &str, value: &str) -> String {
    format!("{node_type}\u{1f}{value}")
}

criterion_group!(benches, bench_search);
criterion_main!(benches);
