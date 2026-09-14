import { env } from '../config/env.js';

function normalizeOrigin(value) {
  return String(value || '')
    .trim()
    .replace(/\/+$/, '');
}

function allowedOrigins() {
  const origins = new Set([normalizeOrigin(env.FRONTEND_URL)]);

  const extra = process.env.CORS_ORIGINS;
  if (extra) {
    for (const part of extra.split(',')) {
      const origin = normalizeOrigin(part);
      if (origin) origins.add(origin);
    }
  }

  return origins;
}

export function originAllowed(origin) {
  if (!origin) return true;

  if (allowedOrigins().has(normalizeOrigin(origin))) return true;

  if (env.NODE_ENV === 'production') return false;

  try {
    const { hostname } = new URL(origin);
    return hostname === 'localhost' || hostname === '127.0.0.1';
  } catch {
    return false;
  }
}
