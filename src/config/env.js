import 'dotenv/config';
import { z } from 'zod';
import { logger } from '../utils/logger.js';

const envSchema = z.object({
  PORT: z.coerce.number().default(3001),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  DB_HOST: z.string().min(1, 'DB_HOST is required'),
  DB_PORT: z.coerce.number().int().min(1).max(65535).default(5432),
  DB_USER: z.string().min(1, 'DB_USER is required'),
  DB_PASSWORD: z.string().min(1, 'DB_PASSWORD is required'),
  DB_NAME: z.string().min(1, 'DB_NAME is required'),
  DB_SCHEMA: z.string().default('public'),
  MASTER_ENCRYPTION_KEY: z
    .string()
    .length(64, 'MASTER_ENCRYPTION_KEY must be 64 hex chars (32 bytes)'),
  JWT_ACCESS_SECRET: z.string().min(32, 'JWT_ACCESS_SECRET is required'),
  JWT_REFRESH_SECRET: z.string().min(32, 'JWT_REFRESH_SECRET is required'),
  JWT_ACCESS_EXPIRES_IN: z.string().default('15m'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),
  FRONTEND_URL: z
    .string()
    .url()
    .default('http://localhost:5173')
    .transform((url) => url.trim().replace(/\/+$/, '')),
  ALLOW_PRIVATE_IPS: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),
  MAX_UPLOAD_BYTES: z.coerce.number().int().positive().default(2_147_483_648),
  SSH_POOL_IDLE_MS: z.coerce.number().int().positive().default(5 * 60 * 1000),
  SSH_POOL_MAX_PER_USER: z.coerce.number().int().positive().default(5),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  logger.error('Invalid environment configuration:');
  logger.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

if (parsed.data.NODE_ENV === 'production' && parsed.data.ALLOW_PRIVATE_IPS) {
  logger.error('ALLOW_PRIVATE_IPS must be false in production.');
  process.exit(1);
}

if (
  parsed.data.NODE_ENV === 'production' &&
  !parsed.data.FRONTEND_URL.startsWith('https://')
) {
  logger.error('FRONTEND_URL must use https in production.');
  process.exit(1);
}

// Keep the rest of the backend code using `env.DATABASE_URL` by deriving it
// from DB_* vars.
const {
  DB_HOST,
  DB_PORT,
  DB_USER,
  DB_PASSWORD,
  DB_NAME,
  DB_SCHEMA,
  ...rest
} = parsed.data;

export const env = {
  ...rest,
  DB_HOST,
  DB_PORT,
  DB_USER,
  DB_PASSWORD,
  DB_NAME,
  DB_SCHEMA,
  DATABASE_URL: `postgresql://${encodeURIComponent(DB_USER)}:${encodeURIComponent(
    DB_PASSWORD,
  )}@${DB_HOST}:${DB_PORT}/${DB_NAME}?schema=${DB_SCHEMA}&sslmode=require`,
};
