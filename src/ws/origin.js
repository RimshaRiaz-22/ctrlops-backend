import { env } from '../config/env.js';

function normalizeOrigin(value) {
  return String(value || '')
    .trim()
    .replace(/\/+$/, '');
}

export function corsAllowedOrigins() {
  const origins = new Set([
    normalizeOrigin(env.FRONTEND_URL),
    'https://ctrlops-frontend-rim.netlify.app',
  ]);

  const extra = process.env.CORS_ORIGINS;
  if (extra) {
    for (const part of extra.split(',')) {
      const origin = normalizeOrigin(part);
      if (origin) origins.add(origin);
    }
  }

  if (env.NODE_ENV !== 'production') {
    origins.add('http://localhost:5173');
    origins.add('http://127.0.0.1:5173');
    origins.add('http://localhost:4173');
  }

  return [...origins].filter(Boolean);
}

export function originAllowed(origin) {
  if (!origin) return true;

  if (corsAllowedOrigins().includes(normalizeOrigin(origin))) return true;

  if (env.NODE_ENV === 'production') return false;

  try {
    const { hostname } = new URL(origin);
    return hostname === 'localhost' || hostname === '127.0.0.1';
  } catch {
    return false;
  }
}
