use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use axum::extract::ws::Message;
use axum::{
    extract::{Path, Query, State, WebSocketUpgrade},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::json;
use tracing::error;
use uuid::Uuid;

use crate::{
    db,
    models::{AlertQuery, ExplorerCategoryQuery, ExplorerEntityQuery, GraphQuery, ListQuery},
    AppState,
};

pub async fn health(State(state): State<AppState>) -> Response {
    let db_ok = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();
    let status = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "ok": db_ok,
            "service": "ioc-graph"
        })),
    )
        .into_response()
}

pub async fn list_iocs(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<impl Serialize>, ApiError> {
    Ok(Json(db::list_iocs(&state.pool, query).await?))
}

pub async fn list_alerts(
    State(state): State<AppState>,
    Query(query): Query<AlertQuery>,
) -> Result<Json<impl Serialize>, ApiError> {
    Ok(Json(db::list_alerts(&state.pool, query).await?))
}

pub async fn explorer_categories(
    State(state): State<AppState>,
    Query(query): Query<ExplorerCategoryQuery>,
) -> Result<Json<impl Serialize>, ApiError> {
    Ok(Json(db::explorer_categories(&state.pool, query).await?))
}

pub async fn explorer_entities(
    State(state): State<AppState>,
    Query(query): Query<ExplorerEntityQuery>,
) -> Result<Json<impl Serialize>, ApiError> {
    Ok(Json(db::explorer_entities(&state.pool, query).await?))
}

pub async fn explorer_entity_details(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    match db::explorer_entity_details(&state.pool, id).await? {
        Some(details) => Ok(Json(details).into_response()),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

pub async fn graph(
    State(state): State<AppState>,
    Query(query): Query<GraphQuery>,
) -> Result<Json<impl Serialize>, ApiError> {
    Ok(Json(db::load_graph(&state.pool, query).await?))
}

pub async fn graph_layer(
    State(state): State<AppState>,
    Path(layer): Path<String>,
    Query(query): Query<GraphQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if layer == "ioc" {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }

    let Some(node_types) = graph_layer_types(&layer) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    let etag = current_layer_etag(&state, &layer, &query).await;
    if etag
        .as_deref()
        .is_some_and(|value| request_etag_matches(&headers, value))
    {
        return Ok(cache_headers(StatusCode::NOT_MODIFIED, etag).into_response());
    }

    let graph = db::load_graph_layer(&state.pool, node_types, query).await?;
    let (status, headers) = cache_headers(StatusCode::OK, etag);
    Ok((status, headers, Json(graph)).into_response())
}

pub async fn ioc_details(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    match db::get_ioc_details(&state.pool, id).await? {
        Some(details) => Ok(Json(details).into_response()),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

pub async fn websocket(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        let mut socket = socket;

        let mut receiver = state.broadcaster.subscribe();
        while let Ok(payload) = receiver.recv().await {
            if socket.send(Message::Text(payload.into())).await.is_err() {
                break;
            }
        }
    })
}

#[derive(Debug)]
pub struct ApiError(anyhow::Error);

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(error: E) -> Self {
        Self(error.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        error!(error = %self.0, "api request failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "internal server error" })),
        )
            .into_response()
    }
}

fn graph_layer_types(layer: &str) -> Option<&'static [&'static str]> {
    match layer {
        "ips" => Some(&["IP"]),
        "domains" => Some(&["Domain"]),
        "hashes" => Some(&["Hash"]),
        "emails" => Some(&["Email"]),
        "cves" => Some(&["CVE"]),
        "urls" => Some(&["URL"]),
        "files" => Some(&["File"]),
        "malware" => Some(&["Malware"]),
        "commands" => Some(&["Command"]),
        "alerts" => Some(&["Alert"]),
        "mitre" => Some(&["MITRE Technique"]),
        "asns" => Some(&["ASN"]),
        "countries" => Some(&["Country"]),
        "sources" => Some(&["Source"]),
        _ => None,
    }
}

async fn current_layer_etag(state: &AppState, layer: &str, query: &GraphQuery) -> Option<String> {
    let fingerprint = state.last_fingerprint.lock().await.clone()?;
    Some(format!(
        "\"ioc-graph-{layer}-{fingerprint}-{:016x}\"",
        graph_query_hash(query)
    ))
}

fn graph_query_hash(query: &GraphQuery) -> u64 {
    let mut hasher = DefaultHasher::new();
    query.types.hash(&mut hasher);
    query.search.hash(&mut hasher);
    query
        .from
        .map(|value| value.timestamp_millis())
        .hash(&mut hasher);
    query
        .to
        .map(|value| value.timestamp_millis())
        .hash(&mut hasher);
    hasher.finish()
}

fn request_etag_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|candidate| candidate.trim() == etag))
}

fn cache_headers(status: StatusCode, etag: Option<String>) -> (StatusCode, HeaderMap) {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, must-revalidate"),
    );

    if let Some(etag) = etag.and_then(|value| HeaderValue::from_str(&value).ok()) {
        headers.insert(header::ETAG, etag);
    }

    (status, headers)
}
