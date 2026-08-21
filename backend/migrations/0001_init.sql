CREATE TABLE IF NOT EXISTS nodes (
    id UUID PRIMARY KEY,
    node_type TEXT NOT NULL,
    value TEXT NOT NULL,
    label TEXT NOT NULL,
    severity TEXT,
    source TEXT,
    description TEXT,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT nodes_type_value_unique UNIQUE (node_type, value)
);

CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT,
    source TEXT NOT NULL,
    description TEXT,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT alerts_source_external_unique UNIQUE (source, external_id)
);

CREATE TABLE IF NOT EXISTS edges (
    id UUID PRIMARY KEY,
    source_node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    target_node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    relation TEXT NOT NULL,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT edges_unique UNIQUE (source_node_id, target_node_id, relation)
);

CREATE INDEX IF NOT EXISTS nodes_type_idx ON nodes(node_type);
CREATE INDEX IF NOT EXISTS nodes_value_idx ON nodes(value);
CREATE INDEX IF NOT EXISTS alerts_last_seen_idx ON alerts(last_seen DESC);
CREATE INDEX IF NOT EXISTS edges_source_idx ON edges(source_node_id);
CREATE INDEX IF NOT EXISTS edges_target_idx ON edges(target_node_id);
