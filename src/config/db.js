import pg from 'pg';
import { env } from './env.js';

const { Pool } = pg;

const globalForDb = globalThis;

export const pool =
  globalForDb.pool ??
  new Pool({
    connectionString: env.DATABASE_URL,
    ssl: { rejectUnauthorized: true },
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  });

if (env.NODE_ENV !== 'production') {
  globalForDb.pool = pool;
}

export async function query(text, params) {
  return pool.query(text, params);
}

export async function checkConnection() {
  const { rows } = await pool.query('SELECT NOW() AS now');
  return rows[0];
}
