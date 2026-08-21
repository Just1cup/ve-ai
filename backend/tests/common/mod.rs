#![allow(dead_code)]

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use ioc_graph_backend::models::{GraphEdge, GraphNode, GraphSnapshot};
use serde_json::{json, Value};
use tempfile::TempDir;
use uuid::Uuid;

pub struct DashboardFixture {
    dir: TempDir,
}

impl DashboardFixture {
    pub fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("create temporary dashboard directory"),
        }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn write_records(&self, name: &str, records: &[Value]) -> PathBuf {
        let path = self.dir.path().join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create synthetic dashboard directory");
        }
        fs::write(
            &path,
            serde_json::to_vec_pretty(records).expect("serialize synthetic dashboard records"),
        )
        .expect("write synthetic dashboard records");
        path
    }

    pub fn write_raw(&self, name: &str, content: impl AsRef<[u8]>) -> PathBuf {
        let path = self.dir.path().join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create synthetic dashboard directory");
        }
        fs::write(&path, content).expect("write synthetic dashboard file");
        path
    }
}

#[derive(Clone, Debug)]
pub struct SyntheticContext {
    pub alert_id: String,
    pub source: String,
    pub region: String,
    pub severity: String,
    pub source_ip: Option<String>,
    pub country: Option<String>,
    pub asn: Option<String>,
    pub org: Option<String>,
    pub file: Option<String>,
    pub hash: Option<String>,
    pub mitre_code: Option<String>,
    pub mitre_label: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub title: String,
}

impl SyntheticContext {
    pub fn indexed(index: usize) -> Self {
        Self {
            alert_id: format!("alert-{index:06}"),
            source: format!("dashboard:source-{}", index % 4),
            region: format!("Region {}", index % 4),
            severity: "high".to_string(),
            source_ip: Some(ip(index)),
            country: Some(country(index)),
            asn: Some(asn(index)),
            org: Some(org(index)),
            file: Some(file(index)),
            hash: Some(hash(index)),
            mitre_code: Some(mitre(index)),
            mitre_label: Some("Command and Control".to_string()),
            first_seen: timestamp(index, 0),
            last_seen: timestamp(index, 5),
            title: format!("Synthetic correlated alert {index}"),
        }
    }

    pub fn alert_id(mut self, value: impl Into<String>) -> Self {
        self.alert_id = value.into();
        self
    }

    pub fn source(mut self, value: impl Into<String>) -> Self {
        self.source = value.into();
        self
    }

    pub fn region(mut self, value: impl Into<String>) -> Self {
        self.region = value.into();
        self
    }

    pub fn source_ip(mut self, value: impl Into<String>) -> Self {
        self.source_ip = Some(value.into());
        self
    }

    pub fn country(mut self, value: impl Into<String>) -> Self {
        self.country = Some(value.into());
        self
    }

    pub fn asn(mut self, value: impl Into<String>) -> Self {
        self.asn = Some(value.into());
        self
    }

    pub fn org(mut self, value: impl Into<String>) -> Self {
        self.org = Some(value.into());
        self
    }

    pub fn file(mut self, value: impl Into<String>) -> Self {
        self.file = Some(value.into());
        self
    }

    pub fn hash(mut self, value: impl Into<String>) -> Self {
        self.hash = Some(value.into());
        self
    }

    pub fn mitre(mut self, code: impl Into<String>, label: impl Into<String>) -> Self {
        self.mitre_code = Some(code.into());
        self.mitre_label = Some(label.into());
        self
    }

    pub fn first_seen(mut self, value: impl Into<String>) -> Self {
        self.first_seen = value.into();
        self
    }

    pub fn last_seen(mut self, value: impl Into<String>) -> Self {
        self.last_seen = value.into();
        self
    }

    pub fn without_geo(mut self) -> Self {
        self.country = None;
        self.asn = None;
        self.org = None;
        self
    }

    pub fn without_file_hash(mut self) -> Self {
        self.file = None;
        self.hash = None;
        self
    }
}

pub fn record(index: usize, ioc_type: &str, value: impl Into<String>) -> Value {
    record_with_context(index, ioc_type, value, SyntheticContext::indexed(index))
}

pub fn record_with_context(
    index: usize,
    ioc_type: &str,
    value: impl Into<String>,
    context: SyntheticContext,
) -> Value {
    let value = value.into();
    let content = alert_content(&context);

    json!({
        "id": format!("event-{index:06}-{ioc_type}"),
        "type": ioc_type,
        "value": value,
        "severity": context.severity,
        "source": context.source,
        "region": context.region,
        "description": content,
        "firstSeen": context.first_seen,
        "lastSeen": context.last_seen,
        "tags": ["synthetic", "ioc-graph-test"],
        "raw": {
            "id": context.alert_id,
            "content": content,
            "region": context.region
        }
    })
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

pub fn duplicated_records(unique_count: usize, repetitions: usize) -> Vec<Value> {
    let mut output = Vec::with_capacity(unique_count * repetitions);
    for repeat in 0..repetitions {
        for index in 0..unique_count {
            let mut context = SyntheticContext::indexed(index)
                .first_seen(timestamp(index, repeat))
                .last_seen(timestamp(index, repeat + 5));
            context.alert_id = format!("shared-alert-{index:06}");
            output.push(record_with_context(
                index + repeat * unique_count,
                "domain",
                domain(index),
                context,
            ));
        }
    }
    output
}

pub fn ip(index: usize) -> String {
    format!("198.51.100.{}", (index % 250) + 1)
}

pub fn domain(index: usize) -> String {
    format!("indicator-{index}.example.test")
}

pub fn url(index: usize) -> String {
    format!("https://{}/download/{}", domain(index), file(index))
}

pub fn hash(index: usize) -> String {
    format!("{index:064x}")
}

pub fn file(index: usize) -> String {
    format!("payload-{index}.exe")
}

pub fn asn(index: usize) -> String {
    format!("AS{}", 13335 + (index % 16))
}

pub fn country(index: usize) -> String {
    const COUNTRIES: [&str; 6] = ["US", "BR", "DE", "NL", "CA", "JP"];
    COUNTRIES[index % COUNTRIES.len()].to_string()
}

pub fn org(index: usize) -> String {
    format!("Example Provider {}", index % 8)
}

pub fn mitre(index: usize) -> String {
    format!("T{:04}", 1000 + (index % 8000))
}

pub fn timestamp(index: usize, minute_offset: usize) -> String {
    let day = (index % 27) + 1;
    let minute = minute_offset % 60;
    format!("2026-01-{day:02}T00:{minute:02}:00Z")
}

pub fn node<'a>(snapshot: &'a GraphSnapshot, node_type: &str, value: &str) -> &'a GraphNode {
    find_node(snapshot, node_type, value).unwrap_or_else(|| {
        panic!("expected node {node_type}:{value} in graph snapshot");
    })
}

pub fn find_node<'a>(
    snapshot: &'a GraphSnapshot,
    node_type: &str,
    value: &str,
) -> Option<&'a GraphNode> {
    snapshot
        .nodes
        .iter()
        .find(|node| node.node_type == node_type && node.value == value)
}

pub fn edges<'a>(
    snapshot: &'a GraphSnapshot,
    source: Uuid,
    target: Uuid,
    relation: &str,
) -> Vec<&'a GraphEdge> {
    snapshot
        .edges
        .iter()
        .filter(|edge| {
            edge.source_node_id == source
                && edge.target_node_id == target
                && edge.relation == relation
        })
        .collect()
}

pub fn has_edge(snapshot: &GraphSnapshot, source: Uuid, target: Uuid, relation: &str) -> bool {
    snapshot.edges.iter().any(|edge| {
        edge.source_node_id == source && edge.target_node_id == target && edge.relation == relation
    })
}

pub fn assert_no_duplicate_nodes(snapshot: &GraphSnapshot) {
    let mut seen = HashSet::new();
    for node in &snapshot.nodes {
        assert!(
            seen.insert((node.node_type.as_str(), node.value.as_str())),
            "duplicate node {}:{}",
            node.node_type,
            node.value
        );
    }
}

pub fn assert_no_duplicate_edges(snapshot: &GraphSnapshot) {
    let mut seen = HashSet::new();
    for edge in &snapshot.edges {
        assert!(
            seen.insert((
                edge.source_node_id,
                edge.target_node_id,
                edge.relation.as_str()
            )),
            "duplicate edge {} -> {} ({})",
            edge.source_node_id,
            edge.target_node_id,
            edge.relation
        );
    }
}

pub fn assert_edges_reference_existing_nodes(snapshot: &GraphSnapshot) {
    let nodes: HashSet<_> = snapshot.nodes.iter().map(|node| node.id).collect();
    for edge in &snapshot.edges {
        assert!(
            nodes.contains(&edge.source_node_id),
            "missing edge source node {}",
            edge.source_node_id
        );
        assert!(
            nodes.contains(&edge.target_node_id),
            "missing edge target node {}",
            edge.target_node_id
        );
    }
}

pub fn node_counts(snapshot: &GraphSnapshot) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for node in &snapshot.nodes {
        *counts.entry(node.node_type.clone()).or_insert(0) += 1;
    }
    counts
}

fn alert_content(context: &SyntheticContext) -> String {
    let mut lines = vec![
        context.title.clone(),
        format!("Severity: {}", context.severity),
        format!(
            "First Seen: {}",
            context.first_seen.replace('T', " ").replace('Z', " UTC")
        ),
        format!(
            "Last Seen: {}",
            context.last_seen.replace('T', " ").replace('Z', " UTC")
        ),
    ];

    if let Some(ip) = &context.source_ip {
        lines.push(format!("Source IP: {ip}"));
    }
    if let Some(country) = &context.country {
        if let Some(asn) = &context.asn {
            let org = context.org.clone().unwrap_or_default();
            lines.push(format!("Country / ASN: {country} / {asn} {org}"));
        } else {
            lines.push(format!("Country: {country}"));
        }
    } else if let Some(asn) = &context.asn {
        let org = context.org.clone().unwrap_or_default();
        lines.push(format!("ASN: {asn} {org}"));
    }

    if let Some(file) = &context.file {
        lines.push("Downloaded Files:".to_string());
        lines.push(format!("- {file}"));
    }

    if let Some(hash) = &context.hash {
        lines.push("SHA256:".to_string());
        lines.push(format!("- {hash}"));
    }

    if let Some(code) = &context.mitre_code {
        lines.push("MITRE ATT&CK:".to_string());
        let label = context.mitre_label.clone().unwrap_or_default();
        lines.push(format!("- {code} {label}"));
    }

    lines.join("\n")
}
