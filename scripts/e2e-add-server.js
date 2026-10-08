/**
 * One-shot local E2E: register → test-connection → create server against local sshd :2222
 * Usage: node scripts/e2e-add-server.js
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const API = process.env.API_URL ?? 'http://127.0.0.1:3001';
const keyPath = path.resolve(__dirname, '../../keys/test');

async function main() {
  const privateKey = fs.readFileSync(keyPath, 'utf8');
  const email = `e2e_${Date.now()}@ctrlops.local`;

  const register = await fetch(`${API}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'password123' }),
  }).then((r) => r.json());

  if (!register.ok) throw new Error(`register failed: ${JSON.stringify(register)}`);
  const token = register.accessToken;

  const payload = {
    name: 'local-ssh',
    type: 'DEVELOPMENT',
    host: '127.0.0.1',
    port: 2222,
    username: process.env.USER || 'macbookpro',
    authMethod: 'KEY',
    privateKey,
  };

  const test = await fetch(`${API}/api/servers/test-connection`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  }).then((r) => r.json());

  console.log('test-connection:', JSON.stringify(test, null, 2));
  if (!test.ok) process.exit(1);

  const created = await fetch(`${API}/api/servers`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  }).then(async (r) => ({ status: r.status, body: await r.json() }));

  console.log('create:', created.status, JSON.stringify(created.body, null, 2));
  if (created.status !== 201 || !created.body.ok) process.exit(1);

  const list = await fetch(`${API}/api/servers`, {
    headers: { Authorization: `Bearer ${token}` },
  }).then((r) => r.json());

  console.log('list count:', list.data?.length);
  console.log('E2E OK');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
