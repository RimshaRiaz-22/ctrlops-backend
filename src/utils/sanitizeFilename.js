import path from 'path';
import { AppError } from '../middleware/errorHandler.js';

export function sanitizeFilename(name) {
  if (typeof name !== 'string' || name.length === 0) {
    throw new AppError('INVALID_FILENAME', 400, 'Filename is required.');
  }
  if (name.includes('\0')) {
    throw new AppError('INVALID_FILENAME', 400, 'Filename contains invalid characters.');
  }

  const base = path.posix.basename(name.replaceAll('\\', '/'));
  if (!base || base === '.' || base === '..') {
    throw new AppError('INVALID_FILENAME', 400, 'Filename is invalid.');
  }
  if (base.includes('/') || base.includes('\\')) {
    throw new AppError('INVALID_FILENAME', 400, 'Filename must not contain a path.');
  }
  return base;
}
