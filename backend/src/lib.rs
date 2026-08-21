pub mod config;
pub mod db;
pub mod ingest;
pub mod models;
pub mod routes;
pub mod watcher;

use std::path::PathBuf;

use axum::{
    http::{header, Method},
    routing::get,
    Router,
};
use sqlx::PgPool;
use tokio::sync::{broadcast, Mutex};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub broadcaster: broadcast::Sender<String>,
    pub dashboard_path: PathBuf,
    pub last_fingerprint: std::sync::Arc<Mutex<Option<String>>>,
}

pub fn app(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET])
        .allow_headers([header::CONTENT_TYPE, header::IF_NONE_MATCH])
        .expose_headers([header::ETAG, header::CACHE_CONTROL]);

    Router::new()
        .route("/api/health", get(routes::health))
        .route("/api/iocs", get(routes::list_iocs))
        .route("/api/iocs/{id}", get(routes::ioc_details))
        .route("/api/alerts", get(routes::list_alerts))
        .route("/api/explorer/categories", get(routes::explorer_categories))
        .route("/api/explorer/entities", get(routes::explorer_entities))
        .route(
            "/api/explorer/entities/{id}",
            get(routes::explorer_entity_details),
        )
        .route("/api/graph", get(routes::graph))
        .route("/api/graph/{layer}", get(routes::graph_layer))
        .route("/api/graph/ioc/{id}", get(routes::ioc_details))
        .route("/api/ws", get(routes::websocket))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
