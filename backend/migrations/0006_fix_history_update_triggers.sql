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
    IF TG_OP = 'UPDATE' THEN
        RETURN NEW;
    END IF;
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
    IF TG_OP = 'UPDATE' THEN
        RETURN NEW;
    END IF;
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
    IF TG_OP = 'UPDATE' THEN
        RETURN NEW;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
