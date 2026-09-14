-- CtrlOps initial schema (PostgreSQL 16)
-- Mirrors data model from 01-architecture-and-foundation.md

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE server_type AS ENUM (
  'PRODUCTION',
  'STAGING',
  'DEVELOPMENT',
  'DATABASE',
  'WEB',
  'DOCKER',
  'OTHER'
);

CREATE TYPE auth_method AS ENUM ('KEY', 'PEM', 'PASSWORD');

CREATE TYPE server_status AS ENUM (
  'ONLINE',
  'OFFLINE',
  'UNKNOWN',
  'AUTH_FAILED'
);

CREATE TABLE users (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email      TEXT NOT NULL UNIQUE,
  password   TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE servers (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  name                 VARCHAR(50) NOT NULL,
  type                 server_type NOT NULL DEFAULT 'OTHER',

  host                 VARCHAR(255) NOT NULL,
  port                 INT NOT NULL DEFAULT 22,
  username             VARCHAR(64) NOT NULL,

  auth_method          auth_method NOT NULL,

  cred_ciphertext      TEXT NOT NULL,
  cred_iv              VARCHAR(32) NOT NULL,
  cred_auth_tag        VARCHAR(32) NOT NULL,
  cred_key_version     INT NOT NULL DEFAULT 1,

  pass_ciphertext      TEXT,
  pass_iv              VARCHAR(32),
  pass_auth_tag        VARCHAR(32),
  pass_key_version     INT,

  proxy_command        TEXT,

  host_key_fingerprint VARCHAR(128),
  host_key_algorithm   VARCHAR(64),

  os_raw               TEXT,
  os_distro            VARCHAR(64),
  os_version           VARCHAR(32),
  os_arch              VARCHAR(32),

  status               server_status NOT NULL DEFAULT 'UNKNOWN',
  last_connected_at    TIMESTAMPTZ,
  last_error           TEXT,

  is_favorite          BOOLEAN NOT NULL DEFAULT FALSE,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT uniq_server_per_user UNIQUE (user_id, host, port, username)
);

CREATE INDEX servers_user_id_created_at_idx ON servers (user_id, created_at DESC);

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER servers_updated_at
  BEFORE UPDATE ON servers
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
