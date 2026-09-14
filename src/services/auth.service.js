import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { query } from '../config/db.js';
import { env } from '../config/env.js';
import { AppError } from '../middleware/errorHandler.js';

const SALT_ROUNDS = 12;

function signAccessToken(userId) {
  return jwt.sign({}, env.JWT_ACCESS_SECRET, {
    subject: userId,
    expiresIn: env.JWT_ACCESS_EXPIRES_IN,
  });
}

function signRefreshToken(userId) {
  return jwt.sign({}, env.JWT_REFRESH_SECRET, {
    subject: userId,
    expiresIn: env.JWT_REFRESH_EXPIRES_IN,
  });
}

function tokensFor(userId) {
  return {
    accessToken: signAccessToken(userId),
    refreshToken: signRefreshToken(userId),
  };
}

export async function register({ email, password }) {
  const existing = await query('SELECT id FROM users WHERE email = $1', [email]);
  if (existing.rows.length > 0) {
    throw new AppError('EMAIL_TAKEN', 409, 'An account with this email already exists.');
  }

  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  const { rows } = await query(
    `INSERT INTO users (email, password)
     VALUES ($1, $2)
     RETURNING id, email, created_at AS "createdAt"`,
    [email, hash],
  );

  const user = rows[0];
  return { user: { id: user.id, email: user.email }, ...tokensFor(user.id) };
}

export async function login({ email, password }) {
  const { rows } = await query(
    'SELECT id, email, password FROM users WHERE email = $1',
    [email],
  );
  const user = rows[0];
  if (!user) {
    throw new AppError('INVALID_CREDENTIALS', 401, 'Invalid email or password.');
  }

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    throw new AppError('INVALID_CREDENTIALS', 401, 'Invalid email or password.');
  }

  return { user: { id: user.id, email: user.email }, ...tokensFor(user.id) };
}

export async function refresh(refreshToken) {
  if (!refreshToken) {
    throw new AppError('UNAUTHORIZED', 401, 'Refresh token required.');
  }

  let payload;
  try {
    payload = jwt.verify(refreshToken, env.JWT_REFRESH_SECRET);
  } catch {
    throw new AppError('UNAUTHORIZED', 401, 'Invalid or expired refresh token.');
  }

  const { rows } = await query('SELECT id, email FROM users WHERE id = $1', [
    payload.sub,
  ]);
  if (!rows[0]) {
    throw new AppError('UNAUTHORIZED', 401, 'User not found.');
  }

  return {
    user: { id: rows[0].id, email: rows[0].email },
    ...tokensFor(rows[0].id),
  };
}
