import { before, afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import app from '../../src/app.js';
import { query } from '../../src/config/db.js';
import { ensureTestDatabase, resetDb } from '../helpers/db.js';
import {
  FAKE_KEY,
  mockSshOk,
  restoreSsh,
  registerUser,
  api,
  serverPayload,
} from '../helpers/http.js';

before(async () => {
  await ensureTestDatabase();
  await resetDb();
});

afterEach(() => {
  restoreSsh();
});

test('US-08 create response has no credential fields and ciphertext is not plaintext', async () => {
  mockSshOk();
  const { token } = await registerUser();
  const res = await api(token).post('/api/servers', serverPayload({ name: 'enc-check' }));

  assert.equal(res.status, 201);
  assert.equal(res.body.ok, true);
  const json = JSON.stringify(res.body);
  assert.equal(json.includes('cred_'), false);
  assert.equal(json.includes('credCiphertext'), false);
  assert.equal(json.includes(FAKE_KEY.slice(0, 20)), false);
  assert.equal(res.body.data.privateKey, undefined);

  const { rows } = await query(
    'SELECT cred_ciphertext, cred_iv, cred_auth_tag, cred_key_version FROM servers WHERE name = $1',
    ['enc-check'],
  );
  assert.equal(rows.length, 1);
  assert.notEqual(rows[0].cred_ciphertext, FAKE_KEY);
  assert.ok(rows[0].cred_iv);
  assert.ok(rows[0].cred_auth_tag);
  assert.equal(rows[0].cred_key_version, 1);
});

test('US-10 other user gets 404 on GET PATCH DELETE', async () => {
  mockSshOk();
  const owner = await registerUser();
  const other = await registerUser();
  const created = await api(owner.token).post(
    '/api/servers',
    serverPayload({ name: 'owned', host: '1.1.1.1', username: 'owner' }),
  );
  assert.equal(created.status, 201);
  const id = created.body.data.id;

  const getRes = await api(other.token).get(`/api/servers/${id}`);
  assert.equal(getRes.status, 404);

  const patchRes = await api(other.token).patch(`/api/servers/${id}`, {
    name: 'hijacked',
  });
  assert.equal(patchRes.status, 404);

  const delRes = await api(other.token).delete(`/api/servers/${id}`);
  assert.equal(delRes.status, 404);

  const listRes = await api(other.token).get('/api/servers');
  assert.equal(listRes.status, 200);
  assert.equal(listRes.body.data.some((s) => s.id === id), false);
});

test('US-11 metadata IP is blocked', async () => {
  const { token } = await registerUser();
  const res = await api(token).post(
    '/api/servers/test-connection',
    serverPayload({ host: '169.254.169.254' }),
  );
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, false);
  assert.equal(res.body.error.code, 'HOST_BLOCKED');
});

test('US-12 eleventh SSH action returns 429', async () => {
  mockSshOk();
  const { token } = await registerUser();
  const payload = serverPayload({ host: '9.9.9.9', username: 'ratelimit' });

  for (let i = 0; i < 10; i += 1) {
    const res = await api(token).post('/api/servers/test-connection', payload);
    assert.equal(res.status, 200);
  }

  const limited = await api(token).post('/api/servers/test-connection', payload);
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error.code, 'RATE_LIMITED');
  assert.ok(limited.body.error.hint);
});

test('US-14 duplicate host+port+username returns 409', async () => {
  mockSshOk();
  const { token } = await registerUser();
  const payload = serverPayload({
    name: 'first',
    host: '4.4.4.4',
    username: 'dup',
  });

  const first = await api(token).post('/api/servers', payload);
  assert.equal(first.status, 201);

  const second = await api(token).post('/api/servers', {
    ...payload,
    name: 'second',
  });
  assert.equal(second.status, 409);
  assert.equal(second.body.error.code, 'DUPLICATE_SERVER');
});

test('unauthenticated server routes return 401', async () => {
  const res = await request(app).get('/api/servers');
  assert.equal(res.status, 401);
});
