import { before, afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import { WebSocket } from 'ws';
import app from '../../src/app.js';
import { attachWs } from '../../src/ws/attach.js';
import { ensureTestDatabase, resetDb } from '../helpers/db.js';
import { mockSshOk, restoreSsh, registerUser, api, serverPayload } from '../helpers/http.js';
import {
  resetPoolForTests,
  inspectPoolForTests,
  pinSession,
  unpinSession,
  setIdleTimeoutForTests,
  poolSize,
} from '../../src/services/sshPool.service.js';
import { resetTicketsForTests } from '../../src/services/terminalTicket.service.js';
import { resetCoordinatorForTests } from '../../src/services/metrics/metricsCoordinator.js';
import { resetMockMetricsTick } from '../../src/services/metrics/mockMetricsOutput.js';
import { resetForTests as resetRegistry } from '../../src/services/terminalRegistry.js';
import {
  upsertHealthSnapshot,
  getHealthSnapshot,
} from '../../src/repositories/healthSnapshot.repository.js';

const prevMock = process.env.MOCK_SSH;

before(async () => {
  process.env.MOCK_SSH = 'true';
  await ensureTestDatabase();
  await resetDb();
});

afterEach(async () => {
  restoreSsh();
  resetCoordinatorForTests();
  resetPoolForTests();
  resetTicketsForTests();
  resetRegistry();
  resetMockMetricsTick();
  process.env.MOCK_SSH = 'true';
});

async function createOwnedServer() {
  mockSshOk();
  const owner = await registerUser();
  const created = await api(owner.token).post(
    '/api/servers',
    serverPayload({ name: `box-${Date.now()}`, host: '1.1.1.1', username: 'ubuntu' }),
  );
  assert.equal(created.status, 201);
  return { owner, id: created.body.data.id };
}

function listenApp() {
  const server = http.createServer(app);
  attachWs(server);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function monitorUrl(server, ticket) {
  const { port } = server.address();
  return `ws://127.0.0.1:${port}/ws/monitor?ticket=${encodeURIComponent(ticket)}`;
}

function openWs(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.once('open', () => resolve(ws));
    ws.once('error', reject);
    ws.once('unexpected-response', (_req, res) => {
      reject(Object.assign(new Error(`upgrade ${res.statusCode}`), { statusCode: res.statusCode }));
    });
  });
}

function waitForType(ws, type, timeout = 4000) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`no ${type}`)), timeout);
    const onMsg = (data) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === type) {
          clearTimeout(t);
          ws.off('message', onMsg);
          resolve(msg);
        }
      } catch {
        /* ignore */
      }
    };
    ws.on('message', onMsg);
  });
}

test('monitor ticket requires auth and ownership', async () => {
  const { owner, id } = await createOwnedServer();
  const other = await registerUser();
  const unauth = await api('').post('/api/monitor/ticket', { serverId: id });
  assert.equal(unauth.status, 401);
  const stolen = await api(other.token).post('/api/monitor/ticket', { serverId: id });
  assert.equal(stolen.status, 404);
  const ok = await api(owner.token).post('/api/monitor/ticket', { serverId: id });
  assert.equal(ok.status, 200);
  assert.ok(ok.body.data.ticket);
});

test('no ticket is 401', async () => {
  const server = await listenApp();
  try {
    await openWs(`ws://127.0.0.1:${server.address().port}/ws/monitor`);
    assert.fail('should reject');
  } catch (err) {
    assert.equal(err.statusCode, 401);
  } finally {
    server.close();
  }
});

test('subscribe mismatch is forbidden; sample arrives; close unpins', async () => {
  const { owner, id } = await createOwnedServer();
  const other = await createOwnedServer();
  const server = await listenApp();
  try {
    const ticketRes = await api(owner.token).post('/api/monitor/ticket', { serverId: id });
    const ws = await openWs(monitorUrl(server, ticketRes.body.data.ticket));
    ws.send(JSON.stringify({ type: 'monitor:subscribe', serverId: other.id }));
    const err = await waitForType(ws, 'monitor:error');
    assert.equal(err.code, 'FORBIDDEN');

    ws.send(JSON.stringify({ type: 'monitor:subscribe', serverId: id }));
    const sample = await waitForType(ws, 'monitor:sample');
    assert.equal(sample.serverId, id);
    assert.ok(sample.memory.total > 0);
    assert.ok(sample.disks.every((d) => !d.mount.startsWith('/snap/')));
    assert.equal(inspectPoolForTests(owner.user.id, id).activeMonitors, 1);

    const listed = await api(owner.token).get(`/api/servers/${id}/files?path=/home/ubuntu`);
    assert.equal(listed.status, 200);
    assert.equal(poolSize(), 1);

    await new Promise((resolve) => {
      ws.once('close', resolve);
      ws.close();
    });
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(inspectPoolForTests(owner.user.id, id).activeMonitors, 0);
  } finally {
    server.close();
  }
});

test('two clients share one poll loop', async () => {
  const { owner, id } = await createOwnedServer();
  const server = await listenApp();
  try {
    const t1 = await api(owner.token).post('/api/monitor/ticket', { serverId: id });
    const t2 = await api(owner.token).post('/api/monitor/ticket', { serverId: id });
    const a = await openWs(monitorUrl(server, t1.body.data.ticket));
    const b = await openWs(monitorUrl(server, t2.body.data.ticket));
    a.send(JSON.stringify({ type: 'monitor:subscribe', serverId: id }));
    await waitForType(a, 'monitor:sample');
    b.send(JSON.stringify({ type: 'monitor:subscribe', serverId: id }));
    await waitForType(b, 'monitor:sample');
    assert.equal(inspectPoolForTests(owner.user.id, id).activeMonitors, 1);
    a.close();
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(inspectPoolForTests(owner.user.id, id).activeMonitors, 1);
    b.close();
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(inspectPoolForTests(owner.user.id, id)?.activeMonitors ?? 0, 0);
  } finally {
    server.close();
  }
});

test('health snapshot upserts one row and appears on list', async () => {
  const { owner, id } = await createOwnedServer();
  await upsertHealthSnapshot({
    serverId: id,
    cpuPercent: 10,
    memoryPercent: 20,
    diskPercent: 30,
    loadAvg1: 0.2,
    uptimeSeconds: 9,
    status: 'HEALTHY',
  });
  await upsertHealthSnapshot({
    serverId: id,
    cpuPercent: 82,
    memoryPercent: 20,
    diskPercent: 30,
    loadAvg1: 0.2,
    uptimeSeconds: 9,
    status: 'WARNING',
  });
  const snap = await getHealthSnapshot(id);
  assert.equal(snap.status, 'WARNING');
  assert.equal(snap.cpuPercent, 82);
  const list = await api(owner.token).get('/api/servers');
  assert.equal(list.body.data[0].health.status, 'WARNING');
  const never = await createOwnedServer();
  const list2 = await api(never.owner.token).get('/api/servers');
  assert.equal(list2.body.data[0].health, null);
});

test('terminal pin survives monitor close; monitor pin survives terminal close; idle evicts when both 0', async () => {
  const { owner, id } = await createOwnedServer();
  setIdleTimeoutForTests(40);
  const server = await listenApp();
  try {
    const t = await api(owner.token).post('/api/monitor/ticket', { serverId: id });
    const ws = await openWs(monitorUrl(server, t.body.data.ticket));
    ws.send(JSON.stringify({ type: 'monitor:subscribe', serverId: id }));
    await waitForType(ws, 'monitor:sample');
    await pinSession(owner.user.id, id);
    ws.close();
    await new Promise((r) => setTimeout(r, 80));
    assert.ok(inspectPoolForTests(owner.user.id, id));
    unpinSession(owner.user.id, id);

    const t2 = await api(owner.token).post('/api/monitor/ticket', { serverId: id });
    const ws2 = await openWs(monitorUrl(server, t2.body.data.ticket));
    ws2.send(JSON.stringify({ type: 'monitor:subscribe', serverId: id }));
    await waitForType(ws2, 'monitor:sample');
    await new Promise((r) => setTimeout(r, 80));
    assert.ok(inspectPoolForTests(owner.user.id, id));
    ws2.close();
    await new Promise((r) => setTimeout(r, 80));
    assert.equal(inspectPoolForTests(owner.user.id, id), null);
  } finally {
    server.close();
  }
});

process.env.MOCK_SSH = prevMock;
