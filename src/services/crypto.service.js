import crypto from 'crypto';
import { env } from '../config/env.js';

const ALGO = 'aes-256-gcm';
const MASTER_KEY = Buffer.from(env.MASTER_ENCRYPTION_KEY, 'hex');

if (MASTER_KEY.length !== 32) {
  throw new Error('MASTER_ENCRYPTION_KEY must be 32 bytes (64 hex chars)');
}

export function encrypt(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, MASTER_KEY, iv);

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
    keyVersion: 1,
  };
}

export function decrypt({ ciphertext, iv, authTag }) {
  const decipher = crypto.createDecipheriv(
    ALGO,
    MASTER_KEY,
    Buffer.from(iv, 'base64'),
  );
  decipher.setAuthTag(Buffer.from(authTag, 'base64'));

  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}
