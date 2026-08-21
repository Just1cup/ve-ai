mod common;

use std::{path::PathBuf, sync::Arc, time::Duration};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use ioc_graph_backend::{app, db, ingest::load_dashboard_snapshot, AppState};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::{broadcast, Mutex};
use tower::ServiceExt;

use common::{domain, record, DashboardFixture};

#[tokio::test]
async fn health_endpoint_returns_503_without_started_database() {
    let response = app(test_state(lazy_unreachable_pool()))
        .oneshot(request("/api/health"))
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body = response_json(response).await;
    assert_eq!(body["service"], "ioc-graph");
    assert_eq!(body["ok"], false);
}

#[tokio::test]
async fn invalid_uuid_path_returns_400_before_database_access() {
    let response = app(test_state(lazy_unreachable_pool()))
        .oneshot(request("/api/iocs/not-a-uuid"))
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invalid_query_parameter_returns_400_before_database_access() {
    let response = app(test_state(lazy_unreachable_pool()))
        .oneshot(request("/api/iocs?limit=not-a-number"))
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invalid_time_filter_returns_400_before_database_access() {
    for uri in [
        "/api/graph/ips?from=not-a-date",
        "/api/explorer/categories?to=not-a-date",
        "/api/explorer/entities?from=not-a-date",
    ] {
        let response = app(test_state(lazy_unreachable_pool()))
            .oneshot(request(uri))
            .await
            .expect("send request");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "uri={uri}");
    }
}

#[tokio::test]
async fn unknown_route_returns_404() {
    let response = app(test_state(lazy_unreachable_pool()))
        .oneshot(request("/api/does-not-exist"))
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unknown_graph_layer_returns_404_before_database_access() {
    let response = app(test_state(lazy_unreachable_pool()))
        .oneshot(request("/api/graph/not-a-layer"))
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn database_backed_endpoint_returns_500_when_database_is_unavailable() {
    let response = app(test_state(lazy_unreachable_pool()))
        .oneshot(request("/api/iocs"))
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
#[ignore = "requires Docker daemon for PostgreSQL Testcontainers"]
async fn database_backed_endpoints_return_200_with_seeded_graph() {
    use testcontainers_modules::{postgres, testcontainers::runners::AsyncRunner};

    let container = postgres::Postgres::default()
        .start()
        .await
        .expect("start postgres testcontainer");
    let host = container.get_host().await.expect("postgres host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("postgres port");
    let database_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let pool = db::connect(&database_url).await.expect("connect postgres");
    db::migrate(&pool).await.expect("run migrations");

    let dashboard = DashboardFixture::new();
    dashboard.write_records("iocs.json", &[record(1, "domain", domain(1))]);
    let snapshot = load_dashboard_snapshot(dashboard.path()).expect("load dashboard");
    db::replace_snapshot(&pool, &snapshot)
        .await
        .expect("seed database");

    let domain = snapshot
        .nodes
        .iter()
        .find(|node| node.node_type == "Domain")
        .expect("domain node");

    for uri in [
        "/api/health".to_string(),
        "/api/iocs?type=Domain&limit=10".to_string(),
        "/api/alerts?limit=10".to_string(),
        "/api/explorer/categories".to_string(),
        "/api/explorer/categories?from=2026-01-01T00:00:00Z&to=2026-01-03T00:00:00Z".to_string(),
        "/api/explorer/entities?type=Domain&limit=10".to_string(),
        "/api/explorer/entities?type=Domain&from=2026-01-01T00:00:00Z&to=2026-01-03T00:00:00Z&limit=10".to_string(),
        "/api/graph?types=Domain".to_string(),
        "/api/graph?types=Domain&from=2026-01-01T00:00:00Z&to=2026-01-03T00:00:00Z".to_string(),
        "/api/graph/ips".to_string(),
        "/api/graph/ips?from=2026-01-01T00:00:00Z&to=2026-01-03T00:00:00Z".to_string(),
        format!("/api/iocs/{}", domain.id),
        format!("/api/explorer/entities/{}", domain.id),
        format!("/api/graph/ioc/{}", domain.id),
    ] {
        let response = app(test_state(pool.clone()))
            .oneshot(request(&uri))
            .await
            .expect("send request");
        assert_eq!(response.status(), StatusCode::OK, "uri={uri}");
    }
}

fn lazy_unreachable_pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgres://ioc_graph:ioc_graph@127.0.0.1:1/ioc_graph")
        .expect("create lazy pg pool")
}

fn test_state(pool: PgPool) -> AppState {
    let (broadcaster, _) = broadcast::channel(8);
    AppState {
        pool,
        broadcaster,
        dashboard_path: PathBuf::from("/tmp/ioc-graph-test-dashboard"),
        last_fingerprint: Arc::new(Mutex::new(None)),
    }
}

fn request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("build request")
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    serde_json::from_slice(&bytes).expect("parse json response")
}
