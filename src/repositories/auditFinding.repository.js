import { query } from '../config/db.js';

const FINDING_COLS = `
  id,
  run_id AS "runId",
  audit_id AS "auditId",
  check_id AS "checkId",
  title,
  category,
  severity,
  status,
  weight,
  detail,
  evidence,
  remediation_text AS "remediationText",
  remediation_command AS "remediationCommand"
`;

function mapFinding(row) {
  if (!row) return null;
  return {
    ...row,
    weight: Number(row.weight ?? 1),
  };
}

export async function insertMany(runId, findings) {
  if (!findings?.length) return [];
  const inserted = [];
  for (const f of findings) {
    try {
      const { rows } = await query(
        `INSERT INTO audit_findings (
           run_id, audit_id, check_id, title, category, severity, status, weight,
           detail, evidence, remediation_text, remediation_command
         ) VALUES (
           $1, $2, $3, $4, $5::audit_category, $6::audit_severity, $7::audit_finding_status, $8,
           $9, $10, $11, $12
         )
         RETURNING ${FINDING_COLS}`,
        [
          runId,
          f.auditId,
          f.checkId,
          f.title,
          f.category,
          f.severity,
          f.status,
          f.weight ?? 1,
          f.detail ?? null,
          f.evidence ?? null,
          f.remediationText ?? null,
          f.remediationCommand ?? null,
        ],
      );
      inserted.push(mapFinding(rows[0]));
    } catch (err) {
      // Server/run deleted mid-flight (FK) — fail soft
      if (err?.code === '23503') {
        return { softFailed: true, inserted, error: err };
      }
      throw err;
    }
  }
  return { softFailed: false, inserted };
}

export async function listByRun(runId) {
  const { rows } = await query(
    `SELECT ${FINDING_COLS} FROM audit_findings
     WHERE run_id = $1
     ORDER BY
       CASE status
         WHEN 'FAIL' THEN 0
         WHEN 'WARNING' THEN 1
         WHEN 'ERROR' THEN 2
         WHEN 'SKIP' THEN 3
         ELSE 4
       END,
       CASE severity
         WHEN 'CRITICAL' THEN 0
         WHEN 'HIGH' THEN 1
         WHEN 'MEDIUM' THEN 2
         WHEN 'LOW' THEN 3
         ELSE 4
       END,
       title`,
    [runId],
  );
  return rows.map(mapFinding);
}
