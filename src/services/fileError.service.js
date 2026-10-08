import { AppError } from '../middleware/errorHandler.js';

const SFTP = {
  EOF: 1,
  NO_SUCH_FILE: 2,
  PERMISSION_DENIED: 3,
  FAILURE: 4,
};

export function mapSftpError(err) {
  if (err instanceof AppError) return err;

  const code = err?.code;
  const numeric = typeof code === 'number' ? code : Number(code);
  const message = err?.message ?? '';

  if (
    numeric === SFTP.NO_SUCH_FILE ||
    code === 'ENOENT' ||
    /no such file/i.test(message)
  ) {
    return new AppError('NOT_FOUND', 404, 'That folder no longer exists.');
  }

  if (
    numeric === SFTP.PERMISSION_DENIED ||
    code === 'EACCES' ||
    /permission denied/i.test(message)
  ) {
    return new AppError(
      'PERMISSION_DENIED',
      403,
      "Permission denied. Your SSH user can't read this folder.",
    );
  }

  if (code === 'ENOTDIR' || /not a directory/i.test(message)) {
    return new AppError('NOT_A_DIRECTORY', 400, "That's a file, not a folder.");
  }

  if (
    numeric === SFTP.FAILURE &&
    /file exists|already exists/i.test(message)
  ) {
    return new AppError('CONFLICT', 409, 'An item with that name already exists.');
  }

  if (
    code === 'ECONNRESET' ||
    code === 'EPIPE' ||
    numeric === 6 ||
    numeric === 7 ||
    /connection lost|no connection/i.test(message)
  ) {
    return new AppError(
      'CONNECTION_LOST',
      502,
      'Lost connection to the server. Reconnecting…',
    );
  }

  return new AppError(
    'FILE_OPERATION_FAILED',
    500,
    'The file operation failed.',
    message ? String(message).slice(0, 200) : undefined,
  );
}
