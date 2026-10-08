import { query } from '../config/db.js';

const COLUMNS = `
  file_manager_layout AS "fileManagerLayout",
  show_hidden_files AS "showHiddenFiles",
  editor_theme AS "editorTheme"
`;

export async function getOrCreate(userId) {
  const existing = await query(
    `SELECT ${COLUMNS} FROM user_preferences WHERE user_id = $1`,
    [userId],
  );
  if (existing.rows[0]) return existing.rows[0];

  const inserted = await query(
    `INSERT INTO user_preferences (user_id)
     VALUES ($1)
     ON CONFLICT (user_id) DO UPDATE SET user_id = EXCLUDED.user_id
     RETURNING ${COLUMNS}`,
    [userId],
  );
  return inserted.rows[0];
}

export async function update(userId, patch) {
  await getOrCreate(userId);
  const sets = [];
  const params = [userId];
  let i = 2;
  if (patch.fileManagerLayout !== undefined) {
    sets.push(`file_manager_layout = $${i++}`);
    params.push(patch.fileManagerLayout);
  }
  if (patch.showHiddenFiles !== undefined) {
    sets.push(`show_hidden_files = $${i++}`);
    params.push(patch.showHiddenFiles);
  }
  if (patch.editorTheme !== undefined) {
    sets.push(`editor_theme = $${i++}`);
    params.push(patch.editorTheme);
  }
  if (sets.length === 0) return getOrCreate(userId);
  const { rows } = await query(
    `UPDATE user_preferences SET ${sets.join(', ')}
     WHERE user_id = $1
     RETURNING ${COLUMNS}`,
    params,
  );
  return rows[0];
}
