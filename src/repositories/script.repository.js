import { query } from '../config/db.js';

const COLUMNS = `
  id,
  name,
  description,
  body,
  tags,
  color,
  run_count AS "runCount",
  last_run_at AS "lastRunAt",
  created_at AS "createdAt",
  updated_at AS "updatedAt"
`;

export async function listByUser(userId) {
  const { rows } = await query(
    `SELECT ${COLUMNS} FROM scripts WHERE user_id = $1 ORDER BY updated_at DESC`,
    [userId],
  );
  return rows;
}

export async function findOwned(id, userId) {
  const { rows } = await query(
    `SELECT ${COLUMNS} FROM scripts WHERE id = $1 AND user_id = $2`,
    [id, userId],
  );
  return rows[0] ?? null;
}

export async function create(userId, { name, description, body, tags, color }) {
  const { rows } = await query(
    `INSERT INTO scripts (user_id, name, description, body, tags, color)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING ${COLUMNS}`,
    [userId, name, description ?? null, body, tags ?? [], color ?? null],
  );
  return rows[0];
}

export async function update(userId, id, patch) {
  const sets = [];
  const params = [id, userId];
  let i = 3;
  if (patch.name !== undefined) {
    sets.push(`name = $${i++}`);
    params.push(patch.name);
  }
  if (patch.description !== undefined) {
    sets.push(`description = $${i++}`);
    params.push(patch.description);
  }
  if (patch.body !== undefined) {
    sets.push(`body = $${i++}`);
    params.push(patch.body);
  }
  if (patch.tags !== undefined) {
    sets.push(`tags = $${i++}`);
    params.push(patch.tags);
  }
  if (patch.color !== undefined) {
    sets.push(`color = $${i++}`);
    params.push(patch.color);
  }
  if (sets.length === 0) return findOwned(id, userId);
  const { rows } = await query(
    `UPDATE scripts SET ${sets.join(', ')}
     WHERE id = $1 AND user_id = $2
     RETURNING ${COLUMNS}`,
    params,
  );
  return rows[0] ?? null;
}

export async function remove(userId, id) {
  const { rowCount } = await query(
    `DELETE FROM scripts WHERE id = $1 AND user_id = $2`,
    [id, userId],
  );
  return rowCount > 0;
}

export async function recordRun(userId, id) {
  const { rows } = await query(
    `UPDATE scripts
     SET run_count = run_count + 1, last_run_at = NOW()
     WHERE id = $1 AND user_id = $2
     RETURNING ${COLUMNS}`,
    [id, userId],
  );
  return rows[0] ?? null;
}
