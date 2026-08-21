CREATE TABLE IF NOT EXISTS node_history (
    history_id BIGSERIAL PRIMARY KEY,
    operation TEXT NOT NULL CHECK (operation IN ('update', 'delete')),
    archived_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    LIKE nodes INCLUDING DEFAULTS
);

CREATE TABLE IF NOT EXISTS alert_history (
    history_id BIGSERIAL PRIMARY KEY,
    operation TEXT NOT NULL CHECK (operation IN ('update', 'delete')),
    archived_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    LIKE alerts INCLUDING DEFAULTS
);

CREATE TABLE IF NOT EXISTS edge_history (
    history_id BIGSERIAL PRIMARY KEY,
    operation TEXT NOT NULL CHECK (operation IN ('update', 'delete')),
    archived_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    LIKE edges INCLUDING DEFAULTS
);

CREATE INDEX IF NOT EXISTS node_history_id_archived_idx
    ON node_history(id, archived_at DESC);
CREATE INDEX IF NOT EXISTS alert_history_id_archived_idx
    ON alert_history(id, archived_at DESC);
CREATE INDEX IF NOT EXISTS edge_history_id_archived_idx
    ON edge_history(id, archived_at DESC);

CREATE OR REPLACE FUNCTION archive_node_version() RETURNS trigger AS $$
BEGIN
    INSERT INTO node_history (
        operation, id, node_type, value, label, severity, source, description,
        first_seen, last_seen, metadata, created_at, updated_at
    ) VALUES (
        lower(TG_OP), OLD.id, OLD.node_type, OLD.value, OLD.label, OLD.severity,
        OLD.source, OLD.description, OLD.first_seen, OLD.last_seen, OLD.metadata,
        OLD.created_at, OLD.updated_at
    );
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION archive_alert_version() RETURNS trigger AS $$
BEGIN
    INSERT INTO alert_history (
        operation, id, node_id, external_id, title, severity, source,
        description, first_seen, last_seen, raw, created_at, updated_at
    ) VALUES (
        lower(TG_OP), OLD.id, OLD.node_id, OLD.external_id, OLD.title,
        OLD.severity, OLD.source, OLD.description, OLD.first_seen, OLD.last_seen,
        OLD.raw, OLD.created_at, OLD.updated_at
    );
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION archive_edge_version() RETURNS trigger AS $$
BEGIN
    INSERT INTO edge_history (
        operation, id, source_node_id, target_node_id, relation, alert_id,
        first_seen, last_seen, metadata, created_at, updated_at
    ) VALUES (
        lower(TG_OP), OLD.id, OLD.source_node_id, OLD.target_node_id,
        OLD.relation, OLD.alert_id, OLD.first_seen, OLD.last_seen, OLD.metadata,
        OLD.created_at, OLD.updated_at
    );
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS nodes_archive_version ON nodes;
CREATE TRIGGER nodes_archive_version
BEFORE UPDATE OR DELETE ON nodes
FOR EACH ROW EXECUTE FUNCTION archive_node_version();

DROP TRIGGER IF EXISTS alerts_archive_version ON alerts;
CREATE TRIGGER alerts_archive_version
BEFORE UPDATE OR DELETE ON alerts
FOR EACH ROW EXECUTE FUNCTION archive_alert_version();

DROP TRIGGER IF EXISTS edges_archive_version ON edges;
CREATE TRIGGER edges_archive_version
BEFORE UPDATE OR DELETE ON edges
FOR EACH ROW EXECUTE FUNCTION archive_edge_version();
