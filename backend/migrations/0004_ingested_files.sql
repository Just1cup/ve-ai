CREATE TABLE IF NOT EXISTS ingested_files (
    path TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    active BOOLEAN NOT NULL DEFAULT true,
    first_ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ingested_files_active_idx
    ON ingested_files(active, last_ingested_at DESC);
