import path from 'path';
import { AppError } from '../middleware/errorHandler.js';

export function safePath(input) {
  if (typeof input !== 'string' || input.length === 0) {
    throw new AppError('INVALID_PATH', 400, 'Path is required.');
  }

  if (input.includes('\0')) {
    throw new AppError('INVALID_PATH', 400, 'Path contains invalid characters.');
  }

  const normalized = path.posix.normalize(input);

  if (!path.posix.isAbsolute(normalized)) {
    throw new AppError('PATH_MUST_BE_ABSOLUTE', 400, 'Path must be absolute.');
  }

  if (normalized.length > 4096) {
    throw new AppError('PATH_TOO_LONG', 400, 'Path is too long.');
  }

  return normalized;
}

export function buildBreadcrumbs(normalizedPath) {
  const breadcrumbs = [{ label: 'Root', path: '/' }];
  if (normalizedPath === '/') return breadcrumbs;

  const parts = normalizedPath.split('/').filter(Boolean);
  let acc = '';
  for (const part of parts) {
    acc += `/${part}`;
    breadcrumbs.push({ label: part, path: acc });
  }
  return breadcrumbs;
}

export function parentPath(normalizedPath) {
  if (normalizedPath === '/') return null;
  const parent = path.posix.dirname(normalizedPath);
  return parent || '/';
}
