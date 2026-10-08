import { before, afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { ensureTestDatabase, resetDb } from '../helpers/db.js';
import { mockSshOk, restoreSsh, registerUser, api, serverPayload } from '../helpers/http.js';
import {
  resetPoolForTests,
  inspectPoolForTests,
  pinSession,
  unpinSession,
} from '../../src/services/sshPool.service.js';

before(async () => {
  process.env.MOCK_SSH = 'true';
  await ensureTestDatabase();
  await resetDb();
});

afterEach(async () => {
  restoreSsh();
  resetPoolForTests();
  process.env.MOCK_SSH = 'true';
});

test('audit run does not break files list and releases refCount', async () => {
  mockSshOk();
  const owner = await registerUser();
  const created = await api(owner.token).post(
    '/api/servers',
    serverPayload({ name: `reg-${Date.now()}`, host: '1.1.1.1', username: 'ubuntu' }),
  );
  assert.equal(created.status, 201);
  const id = created.body.data.id;

  const beforeFiles = await api(owner.token).get(`/api/servers/${id}/files?path=/home/ubuntu`);
  assert.equal(beforeFiles.status, 200);

  await pinSession(owner.user.id, id);

  const started = await api(owner.token).post(`/api/servers/${id}/audits/run`, {
    auditIds: ['ssh-hardening'],
  });
  assert.equal(started.status, 202);

  const start = Date.now();
  let run;
  while (Date.now() - start < 10000) {
    const res = await api(owner.token).get(`/api/audits/runs/${started.body.data.runId}`);
    if (['COMPLETED', 'PARTIAL', 'FAILED'].includes(res.body.data.status)) {
      run = res.body.data;
      break;
    }
    await new Promise((r) => setTimeout(r, 80));
  }
  assert.ok(run);

  const afterFiles = await api(owner.token).get(`/api/servers/${id}/files?path=/home/ubuntu`);
  assert.equal(afterFiles.status, 200);

  const entry = inspectPoolForTests(owner.user.id, id);
  assert.ok(entry);
  assert.equal(entry.refCount, 0);
  assert.equal(entry.activeSessions, 1);

  unpinSession(owner.user.id, id);
});
