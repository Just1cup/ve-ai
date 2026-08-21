use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct GraphNode {
    pub id: Uuid,
    pub node_type: String,
    pub value: String,
    pub label: String,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub description: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub metadata: Value,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct GraphEdge {
    pub id: Uuid,
    pub source_node_id: Uuid,
    pub target_node_id: Uuid,
    pub relation: String,
    pub alert_id: Option<Uuid>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub metadata: Value,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct Alert {
    pub id: Uuid,
    pub node_id: Uuid,
    pub external_id: String,
    pub title: String,
    pub severity: Option<String>,
    pub source: String,
    pub description: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub raw: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct GraphResponse {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub alerts: Vec<Alert>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IocDetails {
    pub node: GraphNode,
    pub alerts: Vec<Alert>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ExplorerCategory {
    pub node_type: String,
    pub total: i64,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ExplorerEntityRow {
    pub id: Uuid,
    pub node_type: String,
    pub value: String,
    pub label: String,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub description: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub metadata: Value,
    pub alert_count: i64,
    pub relationship_count: i64,
    pub observation_count: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExplorerEntityPage {
    pub items: Vec<ExplorerEntityRow>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExplorerEntityDetails {
    pub node: GraphNode,
    pub alerts: Vec<Alert>,
    pub edges: Vec<GraphEdge>,
    pub related_nodes: Vec<GraphNode>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListQuery {
    pub r#type: Option<String>,
    pub search: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GraphQuery {
    pub types: Option<String>,
    pub search: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AlertQuery {
    pub ioc_id: Option<Uuid>,
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExplorerEntityQuery {
    pub r#type: Option<String>,
    pub search: Option<String>,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub sort: Option<String>,
    pub direction: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExplorerCategoryQuery {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct GraphSnapshot {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub alerts: Vec<Alert>,
    pub fingerprint: String,
    pub source_files: Vec<IngestedFile>,
    pub observations: Vec<SourceObservation>,
}

#[derive(Clone, Debug)]
pub struct IngestedFile {
    pub path: String,
    pub fingerprint: String,
    pub size_bytes: i64,
}

#[derive(Clone, Debug)]
pub struct SourceObservation {
    pub source_file_path: String,
    pub source_record_id: String,
    pub content_fingerprint: String,
    pub payload: serde_json::Value,
}
