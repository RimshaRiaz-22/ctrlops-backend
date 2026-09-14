import { query } from '../config/db.js';

export async function logOperation({
  userId,
  serverId,
  operation,
  path,
  fileSize = null,
  success,
  errorCode = null,
}) {
  await query(
    `INSERT INTO file_operation_logs
      (user_id, server_id, operation, path, file_size, success, error_code)
     VALUES ($1, $2, $3::file_operation, $4, $5, $6, $7)`,
    [userId, serverId, operation, path, fileSize, success, errorCode],
  );
}

export async function logSafe(args) {
  try {
    await logOperation(args);
  } catch {
    /* audit must never fail the request */
  }
}
