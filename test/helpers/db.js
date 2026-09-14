import pg from 'pg';
import { env } from '../../src/config/env.js';
import { query } from '../../src/config/db.js';
import { runMigrations } from '../../db/migrate.js';

export async function ensureTestDatabase() {
  const admin = new pg.Client({
    host: env.DB_HOST,
    port: env.DB_PORT,
    user: env.DB_USER,
    password: env.DB_PASSWORD,
    database: 'postgres',
  });

  await admin.connect();
  try {
    const { rows } = await admin.query(
      'SELECT 1 FROM pg_database WHERE datname = $1',
      [env.DB_NAME],
    );
    if (rows.length === 0) {
      await admin.query(`CREATE DATABASE ${env.DB_NAME}`);
    }
  } finally {
    await admin.end();
  }

  await runMigrations(env.DATABASE_URL);
}

export async function resetDb() {
  await query('TRUNCATE servers, users RESTART IDENTITY CASCADE');
}
