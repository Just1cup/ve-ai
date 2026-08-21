CREATE INDEX IF NOT EXISTS edges_relation_idx ON edges(relation);
CREATE INDEX IF NOT EXISTS edges_alert_idx ON edges(alert_id);
CREATE INDEX IF NOT EXISTS nodes_type_last_seen_idx ON nodes(node_type, last_seen DESC);
CREATE INDEX IF NOT EXISTS alerts_node_last_seen_idx ON alerts(node_id, last_seen DESC);
