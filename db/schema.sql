-- runs automatically the first time the postgres container starts
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    host        TEXT,
    app         TEXT,
    pid         INTEGER,
    facility    SMALLINT,
    severity    SMALLINT,
    source_ip   INET,
    message     TEXT NOT NULL,
    raw         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_host ON events (host);
CREATE INDEX IF NOT EXISTS idx_events_app ON events (app);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity);
-- trigram index so the dashboard can do fast "message contains" search later
CREATE INDEX IF NOT EXISTS idx_events_message_trgm ON events USING gin (message gin_trgm_ops);

CREATE TABLE IF NOT EXISTS alerts (
    id        BIGSERIAL PRIMARY KEY,
    ts        TIMESTAMPTZ NOT NULL,
    rule      TEXT NOT NULL,
    entity    TEXT,
    title     TEXT,
    severity  SMALLINT,
    count     INTEGER,
    detail    JSONB
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts DESC);
