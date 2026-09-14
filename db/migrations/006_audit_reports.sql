CREATE TYPE audit_run_status AS ENUM (
  'RUNNING',
  'COMPLETED',
  'FAILED',
  'PARTIAL'
);

CREATE TYPE audit_sudo_mode AS ENUM (
  'ROOT',
  'PASSWORDLESS',
  'UNAVAILABLE'
);

CREATE TYPE audit_category AS ENUM (
  'SERVER',
  'DATABASE',
  'WEB_SERVER',
  'DOCKER'
);

CREATE TYPE audit_severity AS ENUM (
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO'
);

CREATE TYPE audit_finding_status AS ENUM (
  'PASS',
  'WARNING',
  'FAIL',
  'SKIP',
  'ERROR'
);

CREATE TABLE IF NOT EXISTS audit_runs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  server_id       UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  audit_ids       TEXT[] NOT NULL DEFAULT '{}',
  status          audit_run_status NOT NULL DEFAULT 'RUNNING',
  sudo_mode       audit_sudo_mode,
  score           INT,
  grade           VARCHAR(1),
  total_checks    INT NOT NULL DEFAULT 0,
  passed          INT NOT NULL DEFAULT 0,
  warnings        INT NOT NULL DEFAULT 0,
  failed          INT NOT NULL DEFAULT 0,
  skipped         INT NOT NULL DEFAULT 0,
  errored         INT NOT NULL DEFAULT 0,
  os_snapshot     JSONB,
  progress        JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message   TEXT,
  duration_ms     INT,
  started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS audit_runs_server_started_idx
  ON audit_runs (server_id, started_at DESC);

CREATE INDEX IF NOT EXISTS audit_runs_user_started_idx
  ON audit_runs (user_id, started_at DESC);

CREATE INDEX IF NOT EXISTS audit_runs_running_idx
  ON audit_runs (server_id)
  WHERE status = 'RUNNING';

CREATE TABLE IF NOT EXISTS audit_findings (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id               UUID NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
  audit_id             VARCHAR(64) NOT NULL,
  check_id             VARCHAR(64) NOT NULL,
  title                VARCHAR(255) NOT NULL,
  category             audit_category NOT NULL,
  severity             audit_severity NOT NULL,
  status               audit_finding_status NOT NULL,
  weight               INT NOT NULL DEFAULT 1,
  detail               TEXT,
  evidence             TEXT,
  remediation_text     TEXT,
  remediation_command  TEXT
);

CREATE INDEX IF NOT EXISTS audit_findings_run_severity_idx
  ON audit_findings (run_id, severity);
