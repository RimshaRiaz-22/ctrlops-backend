import { query } from '../config/db.js';

const RUN_COLS = `
  id,
  user_id AS "userId",
  server_id AS "serverId",
  audit_ids AS "auditIds",
  status,
  sudo_mode AS "sudoMode",
  score,
  grade,
  total_checks AS "totalChecks",
  passed,
  warnings,
  failed,
  skipped,
  errored,
  os_snapshot AS "osSnapshot",
  progress,
  error_message AS "errorMessage",
  duration_ms AS "durationMs",
  started_at AS "startedAt",
  completed_at AS "completedAt"
`;

function mapRun(row) {
  if (!row) return null;
  return {
    ...row,
    score: row.score == null ? null : Number(row.score),
    totalChecks: Number(row.totalChecks ?? 0),
    passed: Number(row.passed ?? 0),
    warnings: Number(row.warnings ?? 0),
    failed: Number(row.failed ?? 0),
    skipped: Number(row.skipped ?? 0),
    errored: Number(row.errored ?? 0),
    durationMs: row.durationMs == null ? null : Number(row.durationMs),
    progress: row.progress ?? {},
    osSnapshot: row.osSnapshot ?? null,
    auditIds: row.auditIds ?? [],
  };
}

export async function createRunning({ userId, serverId, auditIds }) {
  const { rows } = await query(
    `INSERT INTO audit_runs (user_id, server_id, audit_ids, status, progress)
     VALUES ($1, $2, $3::text[], 'RUNNING', '{}'::jsonb)
     RETURNING ${RUN_COLS}`,
    [userId, serverId, auditIds],
  );
  return mapRun(rows[0]);
}

export async function findOwned(runId, userId) {
  const { rows } = await query(
    `SELECT ${RUN_COLS} FROM audit_runs WHERE id = $1 AND user_id = $2`,
    [runId, userId],
  );
  return mapRun(rows[0]);
}

export async function findRunningByServer(serverId) {
  const { rows } = await query(
    `SELECT ${RUN_COLS} FROM audit_runs
     WHERE server_id = $1 AND status = 'RUNNING'
     ORDER BY started_at DESC
     LIMIT 1`,
    [serverId],
  );
  return mapRun(rows[0]);
}

export async function listByServer(serverId, userId, { limit = 20, offset = 0 } = {}) {
  const { rows } = await query(
    `SELECT ${RUN_COLS} FROM audit_runs
     WHERE server_id = $1 AND user_id = $2
     ORDER BY started_at DESC
     LIMIT $3 OFFSET $4`,
    [serverId, userId, limit, offset],
  );
  return rows.map(mapRun);
}

export async function updateProgress(runId, progress) {
  const { rows } = await query(
    `UPDATE audit_runs SET progress = $2::jsonb WHERE id = $1
     RETURNING ${RUN_COLS}`,
    [runId, JSON.stringify(progress ?? {})],
  );
  return mapRun(rows[0]);
}

export async function setEnv(runId, { sudoMode, osSnapshot }) {
  const { rows } = await query(
    `UPDATE audit_runs
     SET sudo_mode = $2::audit_sudo_mode,
         os_snapshot = $3::jsonb
     WHERE id = $1
     RETURNING ${RUN_COLS}`,
    [runId, sudoMode ?? null, osSnapshot ? JSON.stringify(osSnapshot) : null],
  );
  return mapRun(rows[0]);
}

export async function markFailed(runId, message) {
  const { rows } = await query(
    `UPDATE audit_runs
     SET status = 'FAILED',
         error_message = $2,
         completed_at = NOW(),
         progress = COALESCE(progress, '{}'::jsonb) || jsonb_build_object('message', $2::text)
     WHERE id = $1 AND status = 'RUNNING'
     RETURNING ${RUN_COLS}`,
    [runId, message ?? 'Audit run failed'],
  );
  return mapRun(rows[0]);
}

export async function failAllRunning() {
  const { rowCount } = await query(
    `UPDATE audit_runs
     SET status = 'FAILED',
         error_message = COALESCE(error_message, 'Interrupted by server restart'),
         completed_at = NOW()
     WHERE status = 'RUNNING'`,
  );
  return rowCount ?? 0;
}

export async function finishRun(runId, patch) {
  const {
    status,
    sudoMode,
    score,
    grade,
    totalChecks,
    passed,
    warnings,
    failed,
    skipped,
    errored,
    osSnapshot,
    progress,
    durationMs,
    errorMessage,
  } = patch;

  const { rows } = await query(
    `UPDATE audit_runs SET
       status = $2::audit_run_status,
       sudo_mode = $3::audit_sudo_mode,
       score = $4,
       grade = $5,
       total_checks = $6,
       passed = $7,
       warnings = $8,
       failed = $9,
       skipped = $10,
       errored = $11,
       os_snapshot = $12::jsonb,
       progress = $13::jsonb,
       duration_ms = $14,
       error_message = $15,
       completed_at = NOW()
     WHERE id = $1
     RETURNING ${RUN_COLS}`,
    [
      runId,
      status,
      sudoMode ?? null,
      score ?? null,
      grade ?? null,
      totalChecks ?? 0,
      passed ?? 0,
      warnings ?? 0,
      failed ?? 0,
      skipped ?? 0,
      errored ?? 0,
      osSnapshot ? JSON.stringify(osSnapshot) : null,
      JSON.stringify(progress ?? {}),
      durationMs ?? null,
      errorMessage ?? null,
    ],
  );
  return mapRun(rows[0]);
}

export async function removeOwned(runId, userId) {
  const { rowCount } = await query(
    `DELETE FROM audit_runs WHERE id = $1 AND user_id = $2`,
    [runId, userId],
  );
  return rowCount > 0;
}
