use std::collections::HashMap;

use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

use crate::models::{
    Alert, AlertQuery, ExplorerCategory, ExplorerCategoryQuery, ExplorerEntityDetails,
    ExplorerEntityPage, ExplorerEntityQuery, ExplorerEntityRow, GraphEdge, GraphNode, GraphQuery,
    GraphResponse, GraphSnapshot, IocDetails, ListQuery,
};

pub async fn connect(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(database_url)
        .await?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

pub async fn replace_snapshot(pool: &PgPool, snapshot: &GraphSnapshot) -> Result<()> {
    let mut tx = pool.begin().await?;

    let active_paths: Vec<_> = snapshot
        .source_files
        .iter()
        .map(|file| file.path.clone())
        .collect();
    sqlx::query("UPDATE ingested_files SET active = false WHERE NOT (path = ANY($1))")
        .bind(&active_paths)
        .execute(&mut *tx)
        .await?;
    for file in &snapshot.source_files {
        sqlx::query(
            r#"
            INSERT INTO ingested_files (path, fingerprint, size_bytes, active)
            VALUES ($1, $2, $3, true)
            ON CONFLICT (path) DO UPDATE SET
                fingerprint = EXCLUDED.fingerprint,
                size_bytes = EXCLUDED.size_bytes,
                active = true,
                last_ingested_at = now()
            "#,
        )
        .bind(&file.path)
        .bind(&file.fingerprint)
        .bind(file.size_bytes)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query(
        r#"
        UPDATE observations
        SET active = false, deactivated_at = now()
        WHERE active
          AND source_file_path IN (SELECT path FROM ingested_files WHERE NOT active)
        "#,
    )
    .execute(&mut *tx)
    .await?;

    let mut record_ids_by_file: HashMap<&str, Vec<&str>> = HashMap::new();
    for observation in &snapshot.observations {
        record_ids_by_file
            .entry(&observation.source_file_path)
            .or_default()
            .push(&observation.source_record_id);
    }

    for file in &snapshot.source_files {
        let record_ids = record_ids_by_file
            .get(file.path.as_str())
            .cloned()
            .unwrap_or_default();
        sqlx::query(
            r#"
            UPDATE observations
            SET active = false, deactivated_at = now()
            WHERE source_file_path = $1
              AND active
              AND NOT (source_record_id = ANY($2))
            "#,
        )
        .bind(&file.path)
        .bind(&record_ids)
        .execute(&mut *tx)
        .await?;
    }

    for observation in &snapshot.observations {
        sqlx::query(
            r#"
            UPDATE observations
            SET active = false, deactivated_at = now()
            WHERE source_file_path = $1
              AND source_record_id = $2
              AND content_fingerprint <> $3
              AND active
            "#,
        )
        .bind(&observation.source_file_path)
        .bind(&observation.source_record_id)
        .bind(&observation.content_fingerprint)
        .execute(&mut *tx)
        .await?;

        let result = sqlx::query(
            r#"
            INSERT INTO observations (
                source_file_path, source_record_id, content_fingerprint, payload
            )
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (source_file_path, source_record_id, content_fingerprint)
            DO UPDATE SET active = true, deactivated_at = NULL
            WHERE observations.payload = EXCLUDED.payload
            "#,
        )
        .bind(&observation.source_file_path)
        .bind(&observation.source_record_id)
        .bind(&observation.content_fingerprint)
        .bind(&observation.payload)
        .execute(&mut *tx)
        .await?;
        ensure!(
            result.rows_affected() == 1,
            "observation fingerprint collision for record {} in {}",
            observation.source_record_id,
            observation.source_file_path
        );
    }

    for node in &snapshot.nodes {
        sqlx::query(
            r#"
            INSERT INTO nodes (
                id, node_type, value, label, severity, source, description,
                first_seen, last_seen, metadata
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            ON CONFLICT (node_type, value) DO UPDATE SET
                label = EXCLUDED.label,
                severity = EXCLUDED.severity,
                source = EXCLUDED.source,
                description = EXCLUDED.description,
                first_seen = LEAST(nodes.first_seen, EXCLUDED.first_seen),
                last_seen = GREATEST(nodes.last_seen, EXCLUDED.last_seen),
                metadata = EXCLUDED.metadata,
                updated_at = now()
            WHERE nodes.label IS DISTINCT FROM EXCLUDED.label
               OR nodes.severity IS DISTINCT FROM EXCLUDED.severity
               OR nodes.source IS DISTINCT FROM EXCLUDED.source
               OR nodes.description IS DISTINCT FROM EXCLUDED.description
               OR nodes.first_seen IS DISTINCT FROM EXCLUDED.first_seen
               OR nodes.last_seen IS DISTINCT FROM EXCLUDED.last_seen
               OR nodes.metadata IS DISTINCT FROM EXCLUDED.metadata
            "#,
        )
        .bind(node.id)
        .bind(&node.node_type)
        .bind(&node.value)
        .bind(&node.label)
        .bind(&node.severity)
        .bind(&node.source)
        .bind(&node.description)
        .bind(node.first_seen)
        .bind(node.last_seen)
        .bind(&node.metadata)
        .execute(&mut *tx)
        .await?;
    }

    for alert in &snapshot.alerts {
        sqlx::query(
            r#"
            DELETE FROM alerts
            WHERE source = $1
              AND external_id = $2
              AND id <> $3
            "#,
        )
        .bind(&alert.source)
        .bind(&alert.external_id)
        .bind(alert.id)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO alerts (
                id, node_id, external_id, title, severity, source, description,
                first_seen, last_seen, raw
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            ON CONFLICT (source, external_id) DO UPDATE SET
                title = EXCLUDED.title,
                severity = EXCLUDED.severity,
                description = EXCLUDED.description,
                first_seen = LEAST(alerts.first_seen, EXCLUDED.first_seen),
                last_seen = GREATEST(alerts.last_seen, EXCLUDED.last_seen),
                raw = EXCLUDED.raw,
                updated_at = now()
            WHERE alerts.node_id IS DISTINCT FROM EXCLUDED.node_id
               OR alerts.title IS DISTINCT FROM EXCLUDED.title
               OR alerts.severity IS DISTINCT FROM EXCLUDED.severity
               OR alerts.description IS DISTINCT FROM EXCLUDED.description
               OR alerts.first_seen IS DISTINCT FROM EXCLUDED.first_seen
               OR alerts.last_seen IS DISTINCT FROM EXCLUDED.last_seen
               OR alerts.raw IS DISTINCT FROM EXCLUDED.raw
            "#,
        )
        .bind(alert.id)
        .bind(alert.node_id)
        .bind(&alert.external_id)
        .bind(&alert.title)
        .bind(&alert.severity)
        .bind(&alert.source)
        .bind(&alert.description)
        .bind(alert.first_seen)
        .bind(alert.last_seen)
        .bind(&alert.raw)
        .execute(&mut *tx)
        .await?;
    }

    for edge in &snapshot.edges {
        sqlx::query(
            r#"
            INSERT INTO edges (
                id, source_node_id, target_node_id, relation, alert_id,
                first_seen, last_seen, metadata
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
            ON CONFLICT (source_node_id, target_node_id, relation) DO UPDATE SET
                alert_id = EXCLUDED.alert_id,
                first_seen = LEAST(edges.first_seen, EXCLUDED.first_seen),
                last_seen = GREATEST(edges.last_seen, EXCLUDED.last_seen),
                metadata = EXCLUDED.metadata,
                updated_at = now()
            WHERE edges.alert_id IS DISTINCT FROM EXCLUDED.alert_id
               OR edges.first_seen IS DISTINCT FROM EXCLUDED.first_seen
               OR edges.last_seen IS DISTINCT FROM EXCLUDED.last_seen
               OR edges.metadata IS DISTINCT FROM EXCLUDED.metadata
            "#,
        )
        .bind(edge.id)
        .bind(edge.source_node_id)
        .bind(edge.target_node_id)
        .bind(&edge.relation)
        .bind(edge.alert_id)
        .bind(edge.first_seen)
        .bind(edge.last_seen)
        .bind(&edge.metadata)
        .execute(&mut *tx)
        .await?;
    }

    let edge_ids: Vec<_> = snapshot.edges.iter().map(|edge| edge.id).collect();
    let alert_ids: Vec<_> = snapshot.alerts.iter().map(|alert| alert.id).collect();
    let node_ids: Vec<_> = snapshot.nodes.iter().map(|node| node.id).collect();

    sqlx::query("DELETE FROM edges WHERE NOT (id = ANY($1))")
        .bind(&edge_ids)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM alerts WHERE NOT (id = ANY($1))")
        .bind(&alert_ids)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM nodes WHERE NOT (id = ANY($1))")
        .bind(&node_ids)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}

pub async fn list_iocs(pool: &PgPool, query: ListQuery) -> Result<Vec<GraphNode>> {
    let limit = query.limit.unwrap_or(250).clamp(1, 1000);
    let node_type = query.r#type.filter(|value| !value.trim().is_empty());
    let search = query.search.filter(|value| !value.trim().is_empty());

    let rows = sqlx::query_as::<_, GraphNode>(
        r#"
        SELECT id, node_type, value, label, severity, source, description,
               first_seen, last_seen, metadata
        FROM nodes
        WHERE node_type <> 'Alert'
          AND ($1::text IS NULL OR node_type = $1)
          AND (
              $2::text IS NULL
              OR value ILIKE '%' || $2 || '%'
              OR label ILIKE '%' || $2 || '%'
          )
        ORDER BY last_seen DESC, value ASC
        LIMIT $3
        "#,
    )
    .bind(node_type)
    .bind(search)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

pub async fn list_alerts(pool: &PgPool, query: AlertQuery) -> Result<Vec<Alert>> {
    let limit = query.limit.unwrap_or(100).clamp(1, 500);

    if let Some(ioc_id) = query.ioc_id {
        return sqlx::query_as::<_, Alert>(
            r#"
            SELECT DISTINCT a.id, a.node_id, a.external_id, a.title, a.severity,
                   a.source, a.description, a.first_seen, a.last_seen, a.raw
            FROM alerts a
            JOIN edges e ON e.target_node_id = a.node_id
            WHERE e.source_node_id = $1 AND e.relation = 'seen_in'
            ORDER BY a.last_seen DESC
            LIMIT $2
            "#,
        )
        .bind(ioc_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(Into::into);
    }

    let rows = sqlx::query_as::<_, Alert>(
        r#"
        SELECT id, node_id, external_id, title, severity, source, description,
               first_seen, last_seen, raw
        FROM alerts
        ORDER BY last_seen DESC
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

pub async fn explorer_categories(
    pool: &PgPool,
    query: ExplorerCategoryQuery,
) -> Result<Vec<ExplorerCategory>> {
    let (from, to) = time_bounds(query.from, query.to);

    let rows = sqlx::query_as::<_, ExplorerCategory>(
        r#"
        SELECT node_type, COUNT(*)::bigint AS total
        FROM nodes
        WHERE ($1::timestamptz IS NULL OR last_seen >= $1)
          AND ($2::timestamptz IS NULL OR first_seen <= $2)
        GROUP BY node_type
        ORDER BY node_type ASC
        "#,
    )
    .bind(from)
    .bind(to)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

pub async fn explorer_entities(
    pool: &PgPool,
    query: ExplorerEntityQuery,
) -> Result<ExplorerEntityPage> {
    let limit = query.limit.unwrap_or(50).clamp(1, 250);
    let offset = query.offset.unwrap_or(0).max(0);
    let node_type = query.r#type.filter(|value| !value.trim().is_empty());
    let search = query.search.filter(|value| !value.trim().is_empty());
    let severity = query.severity.filter(|value| !value.trim().is_empty());
    let source = query.source.filter(|value| !value.trim().is_empty());
    let (from, to) = time_bounds(query.from, query.to);
    let sort_key = explorer_sort_key(query.sort.as_deref());
    let direction = explorer_sort_direction(query.direction.as_deref());

    let total = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)::bigint
        FROM nodes n
        WHERE ($1::text IS NULL OR n.node_type = $1)
          AND (
              $2::text IS NULL
              OR n.value ILIKE '%' || $2 || '%'
              OR n.label ILIKE '%' || $2 || '%'
              OR n.metadata::text ILIKE '%' || $2 || '%'
          )
          AND ($3::text IS NULL OR n.severity = $3)
          AND ($4::text IS NULL OR n.source ILIKE '%' || $4 || '%')
          AND ($5::timestamptz IS NULL OR n.last_seen >= $5)
          AND ($6::timestamptz IS NULL OR n.first_seen <= $6)
        "#,
    )
    .bind(&node_type)
    .bind(&search)
    .bind(&severity)
    .bind(&source)
    .bind(from.clone())
    .bind(to.clone())
    .fetch_one(pool)
    .await?;

    let items = sqlx::query_as::<_, ExplorerEntityRow>(
        r#"
        SELECT
            n.id, n.node_type, n.value, n.label, n.severity, n.source,
            n.description, n.first_seen, n.last_seen, n.metadata,
            COALESCE(ac.alert_count, 0)::bigint AS alert_count,
            COALESCE(ec.relationship_count, 0)::bigint AS relationship_count,
            COALESCE(ec.observation_count, 0)::bigint AS observation_count
        FROM nodes n
        LEFT JOIN LATERAL (
            SELECT
                COUNT(*)::bigint AS relationship_count,
                COALESCE(
                    SUM(
                        CASE
                            WHEN jsonb_typeof(e.metadata->'count') = 'number'
                            THEN (e.metadata->>'count')::bigint
                            ELSE 1
                        END
                    ),
                    0
                )::bigint AS observation_count
            FROM edges e
            WHERE (e.source_node_id = n.id OR e.target_node_id = n.id)
              AND ($5::timestamptz IS NULL OR e.last_seen >= $5)
              AND ($6::timestamptz IS NULL OR e.first_seen <= $6)
        ) ec ON true
        LEFT JOIN LATERAL (
            SELECT COUNT(DISTINCT a.id)::bigint AS alert_count
            FROM alerts a
            LEFT JOIN edges e ON e.alert_id = a.id
               OR e.target_node_id = a.node_id
               OR e.source_node_id = a.node_id
            WHERE (a.node_id = n.id
               OR e.source_node_id = n.id
               OR e.target_node_id = n.id)
              AND ($5::timestamptz IS NULL OR a.last_seen >= $5)
              AND ($6::timestamptz IS NULL OR a.first_seen <= $6)
        ) ac ON true
        WHERE ($1::text IS NULL OR n.node_type = $1)
          AND (
              $2::text IS NULL
              OR n.value ILIKE '%' || $2 || '%'
              OR n.label ILIKE '%' || $2 || '%'
              OR n.metadata::text ILIKE '%' || $2 || '%'
          )
          AND ($3::text IS NULL OR n.severity = $3)
          AND ($4::text IS NULL OR n.source ILIKE '%' || $4 || '%')
          AND ($5::timestamptz IS NULL OR n.last_seen >= $5)
          AND ($6::timestamptz IS NULL OR n.first_seen <= $6)
        ORDER BY
            CASE WHEN $9 = 'ioc' AND $10 = 'asc' THEN n.value END ASC,
            CASE WHEN $9 = 'ioc' AND $10 = 'desc' THEN n.value END DESC,
            CASE WHEN $9 = 'type' AND $10 = 'asc' THEN n.node_type END ASC,
            CASE WHEN $9 = 'type' AND $10 = 'desc' THEN n.node_type END DESC,
            CASE WHEN $9 = 'threat' AND $10 = 'asc' THEN n.severity END ASC,
            CASE WHEN $9 = 'threat' AND $10 = 'desc' THEN n.severity END DESC,
            CASE WHEN $9 = 'source' AND $10 = 'asc' THEN n.source END ASC,
            CASE WHEN $9 = 'source' AND $10 = 'desc' THEN n.source END DESC,
            CASE WHEN $9 = 'first_seen' AND $10 = 'asc' THEN n.first_seen END ASC,
            CASE WHEN $9 = 'first_seen' AND $10 = 'desc' THEN n.first_seen END DESC,
            CASE WHEN $9 = 'last_seen' AND $10 = 'asc' THEN n.last_seen END ASC,
            CASE WHEN $9 = 'last_seen' AND $10 = 'desc' THEN n.last_seen END DESC,
            CASE WHEN $9 = 'relationships' AND $10 = 'asc' THEN COALESCE(ec.relationship_count, 0) END ASC,
            CASE WHEN $9 = 'relationships' AND $10 = 'desc' THEN COALESCE(ec.relationship_count, 0) END DESC,
            CASE WHEN $9 = 'observations' AND $10 = 'asc' THEN COALESCE(ec.observation_count, 0) END ASC,
            CASE WHEN $9 = 'observations' AND $10 = 'desc' THEN COALESCE(ec.observation_count, 0) END DESC,
            CASE WHEN $9 = 'alerts' AND $10 = 'asc' THEN COALESCE(ac.alert_count, 0) END ASC,
            CASE WHEN $9 = 'alerts' AND $10 = 'desc' THEN COALESCE(ac.alert_count, 0) END DESC,
            CASE
                WHEN $9 = 'score' AND $10 = 'asc'
                 AND n.metadata->>'score' ~ '^-?[0-9]+(\.[0-9]+)?$'
                THEN (n.metadata->>'score')::numeric
            END ASC,
            CASE
                WHEN $9 = 'score' AND $10 = 'desc'
                 AND n.metadata->>'score' ~ '^-?[0-9]+(\.[0-9]+)?$'
                THEN (n.metadata->>'score')::numeric
            END DESC,
            CASE
                WHEN $9 = 'confidence' AND $10 = 'asc'
                 AND n.metadata->>'confidence' ~ '^-?[0-9]+(\.[0-9]+)?$'
                THEN (n.metadata->>'confidence')::numeric
            END ASC,
            CASE
                WHEN $9 = 'confidence' AND $10 = 'desc'
                 AND n.metadata->>'confidence' ~ '^-?[0-9]+(\.[0-9]+)?$'
                THEN (n.metadata->>'confidence')::numeric
            END DESC,
            n.last_seen DESC,
            n.value ASC
        LIMIT $7 OFFSET $8
        "#,
    )
        .bind(&node_type)
        .bind(&search)
        .bind(&severity)
        .bind(&source)
        .bind(from.clone())
        .bind(to.clone())
        .bind(limit)
        .bind(offset)
        .bind(sort_key)
        .bind(direction)
        .fetch_all(pool)
        .await?;

    Ok(ExplorerEntityPage {
        items,
        total,
        limit,
        offset,
    })
}

pub async fn explorer_entity_details(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<ExplorerEntityDetails>> {
    let Some(details) = get_ioc_details(pool, id).await? else {
        return Ok(None);
    };

    let mut related_ids = Vec::with_capacity(details.edges.len());
    for edge in &details.edges {
        if edge.source_node_id == id {
            related_ids.push(edge.target_node_id);
        } else {
            related_ids.push(edge.source_node_id);
        }
    }
    related_ids.sort_unstable();
    related_ids.dedup();

    let related_nodes = if related_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as::<_, GraphNode>(
            r#"
            SELECT id, node_type, value, label, severity, source, description,
                   first_seen, last_seen, metadata
            FROM nodes
            WHERE id = ANY($1)
            ORDER BY node_type, value
            "#,
        )
        .bind(&related_ids)
        .fetch_all(pool)
        .await?
    };

    Ok(Some(ExplorerEntityDetails {
        node: details.node,
        alerts: details.alerts,
        edges: details.edges,
        related_nodes,
    }))
}

fn explorer_sort_key(sort: Option<&str>) -> &'static str {
    match sort {
        Some("ioc") | Some("value") => "ioc",
        Some("type") => "type",
        Some("score") => "score",
        Some("confidence") => "confidence",
        Some("threat") | Some("severity") => "threat",
        Some("first_seen") => "first_seen",
        Some("relationships") => "relationships",
        Some("observations") => "observations",
        Some("alerts") => "alerts",
        Some("source") => "source",
        _ => "last_seen",
    }
}

fn explorer_sort_direction(direction: Option<&str>) -> &'static str {
    if direction.is_some_and(|value| value.eq_ignore_ascii_case("asc")) {
        "asc"
    } else {
        "desc"
    }
}

fn time_bounds(
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    match (from, to) {
        (Some(from), Some(to)) if from > to => (Some(to), Some(from)),
        values => values,
    }
}

pub async fn load_graph(pool: &PgPool, query: GraphQuery) -> Result<GraphResponse> {
    let types = query.types.filter(|value| !value.trim().is_empty());
    let search = query.search.filter(|value| !value.trim().is_empty());
    let (from, to) = time_bounds(query.from, query.to);

    let nodes = sqlx::query_as::<_, GraphNode>(
        r#"
        WITH selected AS (
            SELECT id
            FROM nodes
            WHERE ($1::text IS NULL OR node_type = ANY(string_to_array($1, ',')))
              AND (
                  $2::text IS NULL
                  OR value ILIKE '%' || $2 || '%'
                  OR label ILIKE '%' || $2 || '%'
              )
              AND ($3::timestamptz IS NULL OR last_seen >= $3)
              AND ($4::timestamptz IS NULL OR first_seen <= $4)
        ),
        expanded AS (
            SELECT id FROM selected
            UNION
            SELECT e.source_node_id
            FROM edges e
            JOIN selected s ON s.id = e.target_node_id
            WHERE ($3::timestamptz IS NULL OR e.last_seen >= $3)
              AND ($4::timestamptz IS NULL OR e.first_seen <= $4)
            UNION
            SELECT e.target_node_id
            FROM edges e
            JOIN selected s ON s.id = e.source_node_id
            WHERE ($3::timestamptz IS NULL OR e.last_seen >= $3)
              AND ($4::timestamptz IS NULL OR e.first_seen <= $4)
        )
        SELECT id, node_type, value, label, severity, source, description,
               first_seen, last_seen, metadata
        FROM nodes
        WHERE id IN (SELECT id FROM expanded)
        ORDER BY node_type, value
        "#,
    )
    .bind(types)
    .bind(search)
    .bind(from.clone())
    .bind(to.clone())
    .fetch_all(pool)
    .await?;

    let node_ids: Vec<Uuid> = nodes.iter().map(|node| node.id).collect();

    let edges = sqlx::query_as::<_, GraphEdge>(
        r#"
        SELECT id, source_node_id, target_node_id, relation, alert_id,
               first_seen, last_seen, metadata
        FROM edges
        WHERE source_node_id = ANY($1) AND target_node_id = ANY($1)
          AND ($2::timestamptz IS NULL OR last_seen >= $2)
          AND ($3::timestamptz IS NULL OR first_seen <= $3)
        ORDER BY relation
        "#,
    )
    .bind(&node_ids)
    .bind(from.clone())
    .bind(to.clone())
    .fetch_all(pool)
    .await?;

    let alerts = sqlx::query_as::<_, Alert>(
        r#"
        SELECT DISTINCT a.id, a.node_id, a.external_id, a.title, a.severity,
               a.source, a.description, a.first_seen, a.last_seen, '{}'::jsonb AS raw
        FROM alerts a
        WHERE (a.node_id = ANY($1)
           OR a.id = ANY(
               SELECT alert_id FROM edges
               WHERE alert_id IS NOT NULL
                 AND source_node_id = ANY($1)
                 AND target_node_id = ANY($1)
                 AND ($2::timestamptz IS NULL OR last_seen >= $2)
                 AND ($3::timestamptz IS NULL OR first_seen <= $3)
           ))
          AND ($2::timestamptz IS NULL OR a.last_seen >= $2)
          AND ($3::timestamptz IS NULL OR a.first_seen <= $3)
        ORDER BY a.last_seen DESC
        "#,
    )
    .bind(&node_ids)
    .bind(from.clone())
    .bind(to.clone())
    .fetch_all(pool)
    .await?;

    Ok(GraphResponse {
        nodes,
        edges,
        alerts,
        generated_at: Utc::now(),
    })
}

pub async fn load_graph_layer(
    pool: &PgPool,
    node_types: &[&str],
    query: GraphQuery,
) -> Result<GraphResponse> {
    let node_types: Vec<String> = node_types
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    let search = query.search.filter(|value| !value.trim().is_empty());
    let (from, to) = time_bounds(query.from, query.to);

    let nodes = sqlx::query_as::<_, GraphNode>(
        r#"
        SELECT id, node_type, value, label, severity, source, description,
               first_seen, last_seen, metadata
        FROM nodes
        WHERE node_type = ANY($1)
          AND (
              $2::text IS NULL
              OR value ILIKE '%' || $2 || '%'
              OR label ILIKE '%' || $2 || '%'
          )
          AND ($3::timestamptz IS NULL OR last_seen >= $3)
          AND ($4::timestamptz IS NULL OR first_seen <= $4)
        ORDER BY node_type, value
        "#,
    )
    .bind(&node_types)
    .bind(search)
    .bind(from.clone())
    .bind(to.clone())
    .fetch_all(pool)
    .await?;

    let node_ids: Vec<Uuid> = nodes.iter().map(|node| node.id).collect();

    let edges = sqlx::query_as::<_, GraphEdge>(
        r#"
        SELECT id, source_node_id, target_node_id, relation, alert_id,
               first_seen, last_seen, metadata
        FROM edges
        WHERE (source_node_id = ANY($1) OR target_node_id = ANY($1))
          AND ($2::timestamptz IS NULL OR last_seen >= $2)
          AND ($3::timestamptz IS NULL OR first_seen <= $3)
        ORDER BY relation
        "#,
    )
    .bind(&node_ids)
    .bind(from.clone())
    .bind(to.clone())
    .fetch_all(pool)
    .await?;

    let edge_alert_ids: Vec<Uuid> = edges.iter().filter_map(|edge| edge.alert_id).collect();
    let alerts = sqlx::query_as::<_, Alert>(
        r#"
        SELECT DISTINCT a.id, a.node_id, a.external_id, a.title, a.severity,
               a.source, a.description, a.first_seen, a.last_seen, '{}'::jsonb AS raw
        FROM alerts a
        WHERE (a.node_id = ANY($1)
           OR a.id = ANY($2))
          AND ($3::timestamptz IS NULL OR a.last_seen >= $3)
          AND ($4::timestamptz IS NULL OR a.first_seen <= $4)
        ORDER BY a.last_seen DESC
        "#,
    )
    .bind(&node_ids)
    .bind(&edge_alert_ids)
    .bind(from.clone())
    .bind(to.clone())
    .fetch_all(pool)
    .await?;

    Ok(GraphResponse {
        nodes,
        edges,
        alerts,
        generated_at: Utc::now(),
    })
}

pub async fn get_ioc_details(pool: &PgPool, id: Uuid) -> Result<Option<IocDetails>> {
    let node = sqlx::query_as::<_, GraphNode>(
        r#"
        SELECT id, node_type, value, label, severity, source, description,
               first_seen, last_seen, metadata
        FROM nodes
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    let Some(node) = node else {
        return Ok(None);
    };

    let alerts = list_alerts(
        pool,
        AlertQuery {
            ioc_id: Some(id),
            limit: Some(100),
        },
    )
    .await?;

    let edges = sqlx::query_as::<_, GraphEdge>(
        r#"
        SELECT id, source_node_id, target_node_id, relation, alert_id,
               first_seen, last_seen, metadata
        FROM edges
        WHERE source_node_id = $1 OR target_node_id = $1
        ORDER BY relation
        "#,
    )
    .bind(id)
    .fetch_all(pool)
    .await?;

    Ok(Some(IocDetails {
        node,
        alerts,
        edges,
    }))
}
