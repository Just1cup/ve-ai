#![allow(dead_code)]

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    path::Path,
};

use ioc_graph_backend::{
    ingest::load_dashboard_snapshot,
    models::{GraphNode, GraphSnapshot},
};
use serde_json::{json, Value};
use tempfile::TempDir;
use uuid::Uuid;

pub const GRAPH_SIZES: &[usize] = &[100, 500, 1_000, 5_000, 10_000, 50_000, 100_000];
pub const MEMORY_SIZES: &[usize] = &[100, 1_000, 10_000, 100_000];
pub const SEARCH_SIZES: &[usize] = &[1_000, 10_000, 100_000, 1_000_000];
pub const WEBSOCKET_CLIENTS: &[usize] = &[10, 100, 500, 1_000];
pub const PARSER_BYTES: &[usize] = &[
    1_024,
    10 * 1_024,
    100 * 1_024,
    1_024 * 1_024,
    10 * 1_024 * 1_024,
    50 * 1_024 * 1_024,
];

pub struct BenchDashboard {
    dir: TempDir,
}

impl BenchDashboard {
    pub fn with_records(records: &[Value]) -> Self {
        let dir = tempfile::tempdir().expect("create benchmark dashboard");
        fs::write(
            dir.path().join("iocs.json"),
            serde_json::to_vec(records).expect("serialize benchmark records"),
        )
        .expect("write benchmark records");
        Self { dir }
    }

    pub fn with_json_bytes(target_bytes: usize) -> Self {
        let dir = tempfile::tempdir().expect("create parser benchmark dashboard");
        let payload = json_payload_approx_bytes(target_bytes);
        fs::write(dir.path().join("iocs.json"), payload).expect("write parser benchmark payload");
        Self { dir }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

pub fn load_snapshot(records: &[Value]) -> GraphSnapshot {
    let dashboard = BenchDashboard::with_records(records);
    load_dashboard_snapshot(dashboard.path()).expect("load benchmark snapshot")
}

pub fn records(count: usize) -> Vec<Value> {
    (0..count)
        .map(|index| {
            let ioc_type = match index % 5 {
                0 => "ip",
                1 => "domain",
                2 => "url",
                3 => "hash",
                _ => "file",
            };
            let value = match ioc_type {
                "ip" => ip(index),
                "domain" => domain(index),
                "url" => url(index),
                "hash" => hash(index),
                "file" => file(index),
                _ => unreachable!(),
            };
            record(index, ioc_type, value)
        })
        .collect()
}

pub fn duplicate_domain_records(unique_count: usize, repetitions: usize) -> Vec<Value> {
    let mut output = Vec::with_capacity(unique_count * repetitions);
    for repetition in 0..repetitions {
        for index in 0..unique_count {
            output.push(record_with_context(
                index + repetition * unique_count,
                "domain",
                domain(index),
                ip(index),
                asn(index),
                hash(index),
                file(index),
                format!("dedup-alert-{index:06}"),
            ));
        }
    }
    output
}

pub fn record(index: usize, ioc_type: &str, value: impl Into<String>) -> Value {
    record_with_context(
        index,
        ioc_type,
        value,
        ip(index),
        asn(index),
        hash(index),
        file(index),
        format!("alert-{index:06}"),
    )
}

pub fn record_with_context(
    index: usize,
    ioc_type: &str,
    value: impl Into<String>,
    source_ip: String,
    asn: String,
    hash: String,
    file: String,
    alert_id: String,
) -> Value {
    let value = value.into();
    let content = format!(
        "Synthetic alert {index}\nSeverity: high\nFirst Seen: 2026-01-01 00:00:00 UTC\nLast Seen: 2026-01-01 00:05:00 UTC\nSource IP: {source_ip}\nCountry / ASN: US / {asn} Example Provider\nDownloaded Files:\n- {file}\nSHA256:\n- {hash}\nMITRE ATT&CK:\n- T1105 Ingress Tool Transfer"
    );

    json!({
        "id": format!("event-{index:06}"),
        "type": ioc_type,
        "value": value,
        "severity": "high",
        "source": format!("benchmark-source-{}", index % 4),
        "description": content,
        "firstSeen": "2026-01-01T00:00:00Z",
        "lastSeen": "2026-01-01T00:05:00Z",
        "raw": {
            "id": alert_id,
            "content": content
        }
    })
}

pub fn json_payload_approx_bytes(target_bytes: usize) -> Vec<u8> {
    let mut records = Vec::new();
    let mut size = 2;

    while size < target_bytes {
        let item = record(records.len(), "domain", domain(records.len()));
        size += serde_json::to_vec(&item).expect("serialize record").len() + 1;
        records.push(item);
    }

    serde_json::to_vec(&records).expect("serialize parser payload")
}

pub fn ip(index: usize) -> String {
    format!("198.51.100.{}", (index % 250) + 1)
}

pub fn domain(index: usize) -> String {
    format!("bench-{index}.example.test")
}

pub fn url(index: usize) -> String {
    format!("https://{}/{}", domain(index), file(index))
}

pub fn hash(index: usize) -> String {
    format!("{index:064x}")
}

pub fn file(index: usize) -> String {
    format!("bench-payload-{index}.exe")
}

pub fn asn(index: usize) -> String {
    format!("AS{}", 13335 + (index % 64))
}

pub fn rss_bytes() -> Option<u64> {
    let statm = fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(resident_pages * 4096)
}

pub fn topology_levels(snapshot: &GraphSnapshot) -> HashMap<Uuid, usize> {
    let mut adjacency: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for edge in &snapshot.edges {
        adjacency
            .entry(edge.source_node_id)
            .or_default()
            .push(edge.target_node_id);
        adjacency
            .entry(edge.target_node_id)
            .or_default()
            .push(edge.source_node_id);
    }

    let source_ids: Vec<_> = snapshot
        .nodes
        .iter()
        .filter(|node| node.node_type == "Source")
        .map(|node| node.id)
        .collect();

    let mut levels = HashMap::new();
    let mut queue = VecDeque::new();
    for id in source_ids {
        levels.insert(id, 0);
        queue.push_back(id);
    }

    while let Some(current) = queue.pop_front() {
        let level = levels[&current];
        for next in adjacency.get(&current).into_iter().flatten() {
            if levels.contains_key(next) {
                continue;
            }
            levels.insert(*next, level + 1);
            queue.push_back(*next);
        }
    }

    levels
}

pub fn assert_deduplicated(snapshot: &GraphSnapshot) {
    let mut nodes = HashSet::new();
    for node in &snapshot.nodes {
        assert!(
            nodes.insert((node.node_type.as_str(), node.value.as_str())),
            "duplicate node {}:{}",
            node.node_type,
            node.value
        );
    }

    let mut edges = HashSet::new();
    for edge in &snapshot.edges {
        assert!(
            edges.insert((
                edge.source_node_id,
                edge.target_node_id,
                edge.relation.as_str()
            )),
            "duplicate edge"
        );
    }
}

pub fn search_entities(count: usize) -> Vec<GraphNode> {
    (0..count)
        .map(|index| {
            let (node_type, value) = match index % 5 {
                0 => ("IP", ip(index)),
                1 => ("Domain", domain(index)),
                2 => ("Hash", hash(index)),
                3 => ("ASN", asn(index)),
                _ => ("URL", url(index)),
            };
            let node_type = node_type.to_string();
            GraphNode {
                id: Uuid::new_v5(
                    &Uuid::NAMESPACE_URL,
                    format!("{node_type}:{value}").as_bytes(),
                ),
                node_type,
                label: value.clone(),
                value,
                severity: None,
                source: None,
                description: None,
                first_seen: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                last_seen: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                metadata: json!({ "index": index }),
            }
        })
        .collect()
}
