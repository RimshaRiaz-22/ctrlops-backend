import { before, afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { ensureTestDatabase, resetDb } from '../helpers/db.js';
import { mockSshOk, restoreSsh, registerUser, api, serverPayload } from '../helpers/http.js';
import { resetPoolForTests } from '../../src/services/sshPool.service.js';
import * as auditRunRepo from '../../src/repositories/auditRun.repository.js';

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

async function createOwnedServer() {
  mockSshOk();
  const owner = await registerUser();
  const created = await api(owner.token).post(
    '/api/servers',
    serverPayload({ name: `audit-${Date.now()}`, host: '1.1.1.1', username: 'ubuntu' }),
  );
  assert.equal(created.status, 201);
  return { owner, id: created.body.data.id, userId: owner.user.id };
}

async function waitForTerminal(token, runId, timeoutMs = 10000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const res = await api(token).get(`/api/audits/runs/${runId}`);
    assert.equal(res.status, 200);
    const status = res.body.data.status;
    if (status === 'COMPLETED' || status === 'PARTIAL' || status === 'FAILED') {
      return res.body.data;
    }
    await new Promise((r) => setTimeout(r, 80));
  }
  throw new Error('run did not finish');
}

test('catalog requires auth', async () => {
  const res = await api('').get('/api/audits/catalog');
  assert.equal(res.status, 401);
});

test('catalog lists 25 audits all implemented', async () => {
  const owner = await registerUser();
  const res = await api(owner.token).get('/api/audits/catalog');
  assert.equal(res.status, 200);
  assert.equal(res.body.data.audits.length, 25);
  assert.ok(res.body.data.audits.every((a) => a.implemented));
});

test('foreign server sudo-status 404', async () => {
  const { id } = await createOwnedServer();
  const other = await registerUser();
  const res = await api(other.token).get(`/api/servers/${id}/audits/sudo-status`);
  assert.equal(res.status, 404);
});

test('sudo-status returns mode without creating a run', async () => {
  const { owner, id } = await createOwnedServer();
  const res = await api(owner.token).get(`/api/servers/${id}/audits/sudo-status`);
  assert.equal(res.status, 200);
  assert.equal(res.body.data.sudoMode, 'PASSWORDLESS');
  const list = await api(owner.token).get(`/api/servers/${id}/audits/runs`);
  assert.equal(list.status, 200);
  assert.equal(list.body.data.length, 0);
});

test('second run while RUNNING returns 409', async () => {
  const { owner, id, userId } = await createOwnedServer();
  const stuck = await auditRunRepo.createRunning({
    userId,
    serverId: id,
    auditIds: ['ssh-hardening'],
  });
  const conflict = await api(owner.token).post(`/api/servers/${id}/audits/run`, {
    auditIds: ['ssh-hardening'],
  });
  assert.equal(conflict.status, 409);
  await auditRunRepo.markFailed(stuck.id, 'test cleanup');
});

test('run returns 202, polls to findings, pdf and delete work', async () => {
  const { owner, id } = await createOwnedServer();
  const started = await api(owner.token).post(`/api/servers/${id}/audits/run`, {
    auditIds: ['ssh-hardening'],
  });
  assert.equal(started.status, 202);
  assert.ok(started.body.data.runId);

  const run = await waitForTerminal(owner.token, started.body.data.runId);
  assert.ok(['COMPLETED', 'PARTIAL'].includes(run.status), run.status);
  assert.ok(run.findings.length >= 7);
  assert.ok(run.coverage);

  const pdf = await api(owner.token).get(`/api/audits/runs/${run.id}/pdf`);
  assert.equal(pdf.status, 200);
  assert.match(String(pdf.headers['content-type']), /pdf/);

  const del = await api(owner.token).delete(`/api/audits/runs/${run.id}`);
  assert.equal(del.status, 200);
});

test('all Server audits run on mock SSH', async () => {
  const { owner, id } = await createOwnedServer();
  const catalog = await api(owner.token).get('/api/audits/catalog');
  const serverIds = catalog.body.data.audits
    .filter((a) => a.category === 'SERVER' && a.implemented)
    .map((a) => a.id);
  assert.equal(serverIds.length, 7);

  const started = await api(owner.token).post(`/api/servers/${id}/audits/run`, {
    auditIds: serverIds,
  });
  assert.equal(started.status, 202);
  const run = await waitForTerminal(owner.token, started.body.data.runId, 20000);
  assert.ok(['COMPLETED', 'PARTIAL'].includes(run.status), run.status);
  assert.ok(run.findings.length >= 30);
  assert.equal(run.progress.completedAuditIds.length, 7);
});

test('Docker audits SKIP when docker absent on mock', async () => {
  const { owner, id } = await createOwnedServer();
  const started = await api(owner.token).post(`/api/servers/${id}/audits/run`, {
    auditIds: ['docker-daemon-socket'],
  });
  assert.equal(started.status, 202);
  const run = await waitForTerminal(owner.token, started.body.data.runId, 15000);
  assert.ok(['COMPLETED', 'PARTIAL'].includes(run.status), run.status);
  assert.ok(run.findings.length >= 1);
  assert.ok(run.findings.every((f) => f.status === 'SKIP'));
  assert.equal(run.findings.some((f) => f.checkId === 'docker-socket-tcp'), true);
});

test('failAllRunning reaps stale RUNNING rows', async () => {
  const { owner, id, userId } = await createOwnedServer();
  const stuck = await auditRunRepo.createRunning({
    userId,
    serverId: id,
    auditIds: ['ssh-hardening'],
  });
  const n = await auditRunRepo.failAllRunning();
  assert.ok(n >= 1);
  const again = await auditRunRepo.findOwned(stuck.id, userId);
  assert.equal(again.status, 'FAILED');
  void owner;
});

test('no sudo -S in audits sources', async () => {
  const { readFileSync, readdirSync, statSync } = await import('node:fs');
  const { join } = await import('node:path');
  const root = join(process.cwd(), 'src');
  const hits = [];
  function walk(dir) {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (p.endsWith('.js')) {
        const text = readFileSync(p, 'utf8');
        if (text.includes('sudo -S')) hits.push(p);
      }
    }
  }
  walk(root);
  assert.deepEqual(hits, []);
});
