import { query } from '../config/db.js';
import * as healthRepo from './healthSnapshot.repository.js';

const SERVER_TYPES = new Set([
  'PRODUCTION',
  'STAGING',
  'DEVELOPMENT',
  'DATABASE',
  'WEB',
  'DOCKER',
  'OTHER',
]);

function parseTypeFilter(type) {
  if (!type) return [];
  const raw = Array.isArray(type) ? type.flatMap((t) => String(t).split(',')) : String(type).split(',');
  return [...new Set(raw.map((t) => t.trim().toUpperCase()).filter((t) => SERVER_TYPES.has(t)))];
}

/** Columns safe to return to clients — never credential blobs. */
export const PUBLIC_SERVER_COLUMNS = `
  id,
  name,
  type,
  host,
  port,
  username,
  auth_method AS "authMethod",
  status,
  os_distro AS "osDistro",
  os_version AS "osVersion",
  os_arch AS "osArch",
  host_key_fingerprint AS "hostKeyFingerprint",
  host_key_algorithm AS "hostKeyAlgorithm",
  bastion_host_key_fingerprint AS "bastionHostKeyFingerprint",
  bastion_host_key_algorithm AS "bastionHostKeyAlgorithm",
  is_favorite AS "isFavorite",
  last_connected_at AS "lastConnectedAt",
  created_at AS "createdAt"
`;

function publicHealth(snap) {
  if (!snap) return null;
  return {
    status: snap.status,
    cpuPercent: snap.cpuPercent,
    memoryPercent: snap.memoryPercent,
    diskPercent: snap.diskPercent,
    checkedAt: snap.checkedAt,
  };
}

async function withHealth(rows) {
  const list = Array.isArray(rows) ? rows : rows ? [rows] : [];
  if (!list.length) return rows;
  const snaps = await healthRepo.listHealthSnapshots(list.map((r) => r.id));
  const byId = new Map(snaps.map((s) => [s.serverId, s]));
  const mapped = list.map((r) => ({ ...r, health: publicHealth(byId.get(r.id)) }));
  return Array.isArray(rows) ? mapped : mapped[0];
}

export async function listServers({ userId, search, type, favorite }) {
  const clauses = ['user_id = $1'];
  const params = [userId];
  let i = 2;

  if (search) {
    clauses.push(`(name ILIKE $${i} OR host ILIKE $${i} OR username ILIKE $${i})`);
    params.push(`%${search}%`);
    i += 1;
  }
  const types = parseTypeFilter(type);
  if (types.length === 1) {
    clauses.push(`type = $${i}`);
    params.push(types[0]);
    i += 1;
  } else if (types.length > 1) {
    clauses.push(`type::text = ANY($${i}::text[])`);
    params.push(types);
    i += 1;
  }
  if (favorite === true || favorite === 'true') {
    clauses.push('is_favorite = TRUE');
  }

  const { rows } = await query(
    `SELECT ${PUBLIC_SERVER_COLUMNS}
     FROM servers
     WHERE ${clauses.join(' AND ')}
     ORDER BY created_at DESC`,
    params,
  );
  return withHealth(rows);
}

export async function getServerById({ userId, id }) {
  const { rows } = await query(
    `SELECT ${PUBLIC_SERVER_COLUMNS}
     FROM servers
     WHERE id = $1 AND user_id = $2`,
    [id, userId],
  );
  return withHealth(rows[0] ?? null);
}

export async function findOwned(serverId, userId) {
  return getServerCredsForPing({ userId, id: serverId });
}

export async function getServerCredsForPing({ userId, id }) {
  const { rows } = await query(
    `SELECT
       id, host, port, username, auth_method AS "authMethod",
       proxy_command AS "proxyCommand",
       host_key_fingerprint AS "hostKeyFingerprint",
       bastion_host_key_fingerprint AS "bastionHostKeyFingerprint",
       cred_ciphertext AS "credCiphertext",
       cred_iv AS "credIv",
       cred_auth_tag AS "credAuthTag",
       pass_ciphertext AS "passCiphertext",
       pass_iv AS "passIv",
       pass_auth_tag AS "passAuthTag"
     FROM servers
     WHERE id = $1 AND user_id = $2`,
    [id, userId],
  );
  return rows[0] ?? null;
}

export async function updateServer({ userId, id, name, type, isFavorite }) {
  const sets = [];
  const params = [id, userId];
  let i = 3;

  if (name !== undefined) {
    sets.push(`name = $${i++}`);
    params.push(name);
  }
  if (type !== undefined) {
    sets.push(`type = $${i++}`);
    params.push(type);
  }
  if (isFavorite !== undefined) {
    sets.push(`is_favorite = $${i++}`);
    params.push(isFavorite);
  }

  if (sets.length === 0) {
    return getServerById({ userId, id });
  }

  const { rows } = await query(
    `UPDATE servers SET ${sets.join(', ')}
     WHERE id = $1 AND user_id = $2
     RETURNING ${PUBLIC_SERVER_COLUMNS}`,
    params,
  );
  return rows[0] ?? null;
}

export async function createServer(data) {
  const {
    userId,
    name,
    type,
    host,
    port,
    username,
    authMethod,
    credCiphertext,
    credIv,
    credAuthTag,
    credKeyVersion,
    passCiphertext,
    passIv,
    passAuthTag,
    passKeyVersion,
    proxyCommand,
    hostKeyFingerprint,
    hostKeyAlgorithm,
    bastionHostKeyFingerprint,
    bastionHostKeyAlgorithm,
    osRaw,
    osDistro,
    osVersion,
    osArch,
    status,
  } = data;

  const { rows } = await query(
    `INSERT INTO servers (
       user_id, name, type, host, port, username, auth_method,
       cred_ciphertext, cred_iv, cred_auth_tag, cred_key_version,
       pass_ciphertext, pass_iv, pass_auth_tag, pass_key_version,
       proxy_command, host_key_fingerprint, host_key_algorithm,
       bastion_host_key_fingerprint, bastion_host_key_algorithm,
       os_raw, os_distro, os_version, os_arch,
       status, last_connected_at
     ) VALUES (
       $1,$2,$3,$4,$5,$6,$7,
       $8,$9,$10,$11,
       $12,$13,$14,$15,
       $16,$17,$18,
       $19,$20,
       $21,$22,$23,$24,
       $25, NOW()
     )
     RETURNING ${PUBLIC_SERVER_COLUMNS}`,
    [
      userId,
      name,
      type,
      host,
      port,
      username,
      authMethod,
      credCiphertext,
      credIv,
      credAuthTag,
      credKeyVersion ?? 1,
      passCiphertext ?? null,
      passIv ?? null,
      passAuthTag ?? null,
      passKeyVersion ?? null,
      proxyCommand ?? null,
      hostKeyFingerprint ?? null,
      hostKeyAlgorithm ?? null,
      bastionHostKeyFingerprint ?? null,
      bastionHostKeyAlgorithm ?? null,
      osRaw ?? null,
      osDistro ?? null,
      osVersion ?? null,
      osArch ?? null,
      status ?? 'ONLINE',
    ],
  );
  return rows[0];
}

export async function deleteServer({ userId, id }) {
  const { rowCount } = await query(
    'DELETE FROM servers WHERE id = $1 AND user_id = $2',
    [id, userId],
  );
  return rowCount > 0;
}

export async function updateServerStatus({
  userId,
  id,
  status,
  lastError,
  osInfo,
  bastionHostKeyFingerprint,
  bastionHostKeyAlgorithm,
}) {
  const { rows } = await query(
    `UPDATE servers SET
       status = $3::server_status,
       last_error = $4,
       last_connected_at = CASE WHEN $3::server_status = 'ONLINE'::server_status THEN NOW() ELSE last_connected_at END,
       os_distro = COALESCE($5, os_distro),
       os_version = COALESCE($6, os_version),
       os_arch = COALESCE($7, os_arch),
       os_raw = COALESCE($8, os_raw),
       bastion_host_key_fingerprint = COALESCE(bastion_host_key_fingerprint, $9),
       bastion_host_key_algorithm = COALESCE(bastion_host_key_algorithm, $10)
     WHERE id = $1 AND user_id = $2
     RETURNING ${PUBLIC_SERVER_COLUMNS}`,
    [
      id,
      userId,
      status,
      lastError ?? null,
      osInfo?.distro ?? null,
      osInfo?.version ?? null,
      osInfo?.arch ?? null,
      osInfo?.raw ?? null,
      bastionHostKeyFingerprint ?? null,
      bastionHostKeyAlgorithm ?? null,
    ],
  );
  return rows[0] ?? null;
}
