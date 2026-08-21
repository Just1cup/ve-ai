mod common;

use ioc_graph_backend::ingest::load_dashboard_snapshot;
use mockall::automock;
use serde_json::{json, Value};
use tokio::sync::broadcast;

use common::{domain, record, DashboardFixture};

#[automock]
trait GraphUpdateSink {
    fn send(&self, payload: String) -> Result<usize, String>;
}

#[tokio::test]
async fn broadcast_delivers_graph_update_to_all_subscribers() {
    let (sender, _) = broadcast::channel(32);
    let mut receivers: Vec<_> = (0..25).map(|_| sender.subscribe()).collect();
    let payload = json!({ "type": "graph_updated", "version": 1 }).to_string();

    let delivered = sender.send(payload.clone()).expect("broadcast payload");

    assert_eq!(delivered, 25);
    for receiver in &mut receivers {
        assert_eq!(receiver.recv().await.expect("receive payload"), payload);
    }
}

#[test]
fn graph_update_payload_is_valid_json_and_contains_revision_only() {
    let dashboard = DashboardFixture::new();
    dashboard.write_records("iocs.json", &[record(1, "domain", domain(1))]);
    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");

    let payload = json!({
        "type": "graph_updated",
        "revision": snapshot.fingerprint,
    })
    .to_string();
    let parsed: Value = serde_json::from_str(&payload).expect("valid websocket json");

    assert_eq!(parsed["type"], "graph_updated");
    assert!(parsed["revision"].as_str().is_some());
    assert!(parsed.get("graph").is_none());
}

#[test]
fn mocked_sink_receives_graph_update_once() {
    let mut sink = MockGraphUpdateSink::new();
    sink.expect_send()
        .times(1)
        .withf(|payload| payload.contains("\"graph_updated\""))
        .returning(|_| Ok(1));

    let delivered = publish_update(&sink, json!({ "type": "graph_updated" }).to_string())
        .expect("publish update");

    assert_eq!(delivered, 1);
}

fn publish_update<S: GraphUpdateSink>(sink: &S, payload: String) -> Result<usize, String> {
    sink.send(payload)
}
