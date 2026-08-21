CREATE TABLE IF NOT EXISTS observations (
    id BIGSERIAL PRIMARY KEY,
    source_file_path TEXT NOT NULL REFERENCES ingested_files(path) ON DELETE RESTRICT,
    source_record_id TEXT NOT NULL,
    content_fingerprint TEXT NOT NULL,
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    active BOOLEAN NOT NULL DEFAULT true,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deactivated_at TIMESTAMPTZ,
    CONSTRAINT observations_version_unique
        UNIQUE (source_file_path, source_record_id, content_fingerprint),
    CONSTRAINT observations_active_timestamp_check
        CHECK ((active AND deactivated_at IS NULL) OR (NOT active AND deactivated_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS observations_one_active_record_idx
    ON observations(source_file_path, source_record_id)
    WHERE active;

CREATE INDEX IF NOT EXISTS observations_active_file_idx
    ON observations(source_file_path, active);

CREATE INDEX IF NOT EXISTS observations_record_history_idx
    ON observations(source_record_id, ingested_at DESC);
