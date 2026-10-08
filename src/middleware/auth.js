import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import { AppError } from './errorHandler.js';
import { consumeTicket } from '../services/downloadTicket.service.js';

function isTicketDownload(req) {
  const path = req.path ?? '';
  return (
    req.method === 'GET' &&
    /\/files\/download(?:-zip)?$/.test(path)
  );
}

function serverIdFromPath(req) {
  const match = (req.path ?? '').match(/^\/([^/]+)\/files\/download(?:-zip)?$/);
  return match?.[1] ?? req.params.id;
}

export function requireAuth(req, _res, next) {
  const ticket = typeof req.query.ticket === 'string' ? req.query.ticket : '';
  if (ticket) {
    if (!isTicketDownload(req)) {
      return next(new AppError('UNAUTHORIZED', 401, 'Authentication required.'));
    }
    const rec = consumeTicket(ticket);
    const serverId = serverIdFromPath(req);
    if (!rec || rec.serverId !== serverId) {
      return next(new AppError('UNAUTHORIZED', 401, 'Invalid or expired download ticket.'));
    }
    if (rec.kind === 'zip' && !/\/files\/download-zip$/.test(req.path)) {
      return next(new AppError('UNAUTHORIZED', 401, 'Invalid or expired download ticket.'));
    }
    if (rec.kind === 'file' && /\/files\/download-zip$/.test(req.path)) {
      return next(new AppError('UNAUTHORIZED', 401, 'Invalid or expired download ticket.'));
    }
    req.user = { id: rec.userId };
    req.downloadTicket = rec;
    return next();
  }

  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return next(new AppError('UNAUTHORIZED', 401, 'Authentication required.'));
  }

  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, env.JWT_ACCESS_SECRET);
    req.user = { id: payload.sub };
    return next();
  } catch {
    return next(new AppError('UNAUTHORIZED', 401, 'Invalid or expired token.'));
  }
}
