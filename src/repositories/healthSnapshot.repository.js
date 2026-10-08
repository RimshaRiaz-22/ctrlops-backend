import { query } from '../config/db.js';

function mapRow(row) {
  if (!row) return null;
  return {
    serverId: row.serverId,
    cpuPercent: row.cpuPercent == null ? null : Number(row.cpuPercent),
    memoryPercent: row.memoryPercent == null ? null : Number(row.memoryPercent),
    diskPercent: row.diskPercent == null ? null : Number(row.diskPercent),
    loadAvg1: row.loadAvg1 == null ? null : Number(row.loadAvg1),
    uptimeSeconds: row.uptimeSeconds == null ? null : Number(row.uptimeSeconds),
    status: row.status,
    checkedAt: row.checkedAt,
  };
}

export async function upsertHealthSnapshot({
  serverId,
  cpuPercent,
  memoryPercent,
  diskPercent,
  loadAvg1,
  uptimeSeconds,
  status,
}) {
  const { rows } = await query(
    `INSERT INTO server_health_snapshots (
       server_id, cpu_percent, memory_percent, disk_percent,
       load_avg_1, uptime_seconds, status, checked_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7::health_status, NOW())
     ON CONFLICT (server_id) DO UPDATE SET
       cpu_percent = EXCLUDED.cpu_percent,
       memory_percent = EXCLUDED.memory_percent,
       disk_percent = EXCLUDED.disk_percent,
       load_avg_1 = EXCLUDED.load_avg_1,
       uptime_seconds = EXCLUDED.uptime_seconds,
       status = EXCLUDED.status,
       checked_at = NOW()
     RETURNING
       server_id AS "serverId",
       cpu_percent AS "cpuPercent",
       memory_percent AS "memoryPercent",
       disk_percent AS "diskPercent",
       load_avg_1 AS "loadAvg1",
       uptime_seconds AS "uptimeSeconds",
       status,
       checked_at AS "checkedAt"`,
    [
      serverId,
      cpuPercent ?? null,
      memoryPercent ?? null,
      diskPercent ?? null,
      loadAvg1 ?? null,
      uptimeSeconds ?? null,
      status,
    ],
  );
  return mapRow(rows[0]);
}

export async function getHealthSnapshot(serverId) {
  const { rows } = await query(
    `SELECT
       server_id AS "serverId",
       cpu_percent AS "cpuPercent",
       memory_percent AS "memoryPercent",
       disk_percent AS "diskPercent",
       load_avg_1 AS "loadAvg1",
       uptime_seconds AS "uptimeSeconds",
       status,
       checked_at AS "checkedAt"
     FROM server_health_snapshots
     WHERE server_id = $1`,
    [serverId],
  );
  return mapRow(rows[0]);
}

export async function listHealthSnapshots(serverIds) {
  if (!serverIds?.length) return [];
  const { rows } = await query(
    `SELECT
       server_id AS "serverId",
       cpu_percent AS "cpuPercent",
       memory_percent AS "memoryPercent",
       disk_percent AS "diskPercent",
       load_avg_1 AS "loadAvg1",
       uptime_seconds AS "uptimeSeconds",
       status,
       checked_at AS "checkedAt"
     FROM server_health_snapshots
     WHERE server_id = ANY($1::uuid[])`,
    [serverIds],
  );
  return rows.map(mapRow);
}
