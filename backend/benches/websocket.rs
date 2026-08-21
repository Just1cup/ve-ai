mod support;

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde_json::json;
use tokio::{runtime::Runtime, sync::broadcast};

use support::WEBSOCKET_CLIENTS;

fn bench_websocket_broadcast(c: &mut Criterion) {
    let runtime = Runtime::new().expect("create tokio runtime");
    let payload = json!({
        "type": "graph_updated",
        "graph": {
            "nodes": [],
            "edges": [],
            "alerts": []
        }
    })
    .to_string();

    let mut group = c.benchmark_group("websocket_broadcast");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &clients in WEBSOCKET_CLIENTS {
        group.throughput(Throughput::Elements(clients as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(clients),
            &clients,
            |b, &clients| {
                b.iter(|| {
                    runtime.block_on(async {
                        let (sender, _) = broadcast::channel(clients + 1);
                        let mut receivers: Vec<_> =
                            (0..clients).map(|_| sender.subscribe()).collect();
                        let delivered = sender
                            .send(std::hint::black_box(payload.clone()))
                            .expect("broadcast payload");

                        for receiver in &mut receivers {
                            let message = receiver.recv().await.expect("receive payload");
                            std::hint::black_box(message);
                        }

                        std::hint::black_box(delivered)
                    })
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_websocket_broadcast);
criterion_main!(benches);
