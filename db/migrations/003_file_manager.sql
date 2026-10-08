DO $$ BEGIN
  CREATE TYPE file_operation AS ENUM (
    'UPLOAD',
    'DOWNLOAD',
    'DELETE',
    'RENAME',
    'MKDIR',
    'EDIT',
    'UNZIP',
    'ZIP_DOWNLOAD'
  );
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS user_preferences (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  file_manager_layout  VARCHAR(32) NOT NULL DEFAULT 'list',
  show_hidden_files    BOOLEAN NOT NULL DEFAULT FALSE,
  editor_theme         VARCHAR(32) NOT NULL DEFAULT 'dark',
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS user_preferences_updated_at ON user_preferences;
CREATE TRIGGER user_preferences_updated_at
  BEFORE UPDATE ON user_preferences
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS file_operation_logs (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  server_id   UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  operation   file_operation NOT NULL,
  path        TEXT NOT NULL,
  file_size   BIGINT,
  success     BOOLEAN NOT NULL,
  error_code  VARCHAR(64),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS file_operation_logs_server_created_idx
  ON file_operation_logs (server_id, created_at DESC);

CREATE INDEX IF NOT EXISTS file_operation_logs_user_created_idx
  ON file_operation_logs (user_id, created_at DESC);
