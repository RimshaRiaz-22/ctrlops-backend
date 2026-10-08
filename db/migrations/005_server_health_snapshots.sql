CREATE TYPE health_status AS ENUM (
  'HEALTHY',
  'WARNING',
  'CRITICAL',
  'UNREACHABLE',
  'UNKNOWN'
);

CREATE TABLE IF NOT EXISTS server_health_snapshots (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  server_id        UUID NOT NULL UNIQUE REFERENCES servers(id) ON DELETE CASCADE,
  cpu_percent      DOUBLE PRECISION,
  memory_percent   DOUBLE PRECISION,
  disk_percent     DOUBLE PRECISION,
  load_avg_1       DOUBLE PRECISION,
  uptime_seconds   BIGINT,
  status           health_status NOT NULL DEFAULT 'UNKNOWN',
  checked_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS server_health_snapshots_checked_at_idx
  ON server_health_snapshots (checked_at DESC);
