import { env } from '../config/env.js';

export function originAllowed(origin) {
  if (!origin) return true;
  if (env.NODE_ENV === 'production') return origin === env.FRONTEND_URL;
  try {
    const { hostname } = new URL(origin);
    return hostname === 'localhost' || hostname === '127.0.0.1';
  } catch {
    return false;
  }
}
