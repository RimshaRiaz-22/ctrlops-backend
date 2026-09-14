import { before, afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import { WebSocket } from 'ws';
import app from '../../src/app.js';
import { attachTerminalWs } from '../../src/ws/terminal.ws.js';
import { ensureTestDatabase, resetDb } from '../helpers/db.js';
import { mockSshOk, restoreSsh, registerUser, api, serverPayload } from '../helpers/http.js';
import {
  resetPoolForTests,
  poolSize,
  pinSession,
  unpinSession,
  inspectPoolForTests,
  setIdleTimeoutForTests,
  withSftp,
} from '../../src/services/sshPool.service.js';
import { resetTicketsForTests } from '../../src/services/terminalTicket.service.js';
import { resetForTests as resetRegistry } from '../../src/services/terminalRegistry.js';

const prevMock = process.env.MOCK_SSH;

before(async () => {
  process.env.MOCK_SSH = 'true';
  await ensureTestDatabase();
  await resetDb();
});

afterEach(async () => {
  restoreSsh();
  resetPoolForTests();
  resetTicketsForTests();
  resetRegistry();
  process.env.MOCK_SSH = 'true';
});

async function createOwnedServer(username = 'ubuntu') {
  mockSshOk();
  const owner = await registerUser();
  const created = await api(owner.token).post(
    '/api/servers',
    serverPayload({ name: `box-${Date.now()}`, host: '1.1.1.1', username }),
  );
  assert.equal(created.status, 201);
  return { owner, id: created.body.data.id };
}

function listenApp() {
  const server = http.createServer(app);
  attachTerminalWs(server);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function wsUrl(server, ticket) {
  const { port } = server.address();
  return `ws://127.0.0.1:${port}/ws/terminal?ticket=${encodeURIComponent(ticket)}`;
}

function openWs(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    ws.once('open', () => resolve(ws));
    ws.once('error', reject);
    ws.once('unexpected-response', (_req, res) => {
      reject(Object.assign(new Error(`upgrade ${res.statusCode}`), { statusCode: res.statusCode }));
    });
  });
}

function collect(ws) {
  let text = '';
  const controls = [];
  ws.on('message', (data, isBinary) => {
    if (isBinary) {
      text += Buffer.from(data).toString('utf8');
    } else {
      const raw = typeof data === 'string' ? data : data.toString('utf8');
      try {
        controls.push(JSON.parse(raw));
      } catch {
        text += raw;
      }
    }
  });
  return {
    get text() {
      return text;
    },
    get controls() {
      return controls;
    },
    waitFor(pred, ms = 3000) {
      return new Promise((resolve, reject) => {
        const start = Date.now();
        const check = () => {
          if (pred(text, controls)) return resolve({ text, controls });
          if (Date.now() - start > ms) {
            return reject(new Error(`timeout waiting; text=${JSON.stringify(text)} controls=${JSON.stringify(controls)}`));
          }
          setTimeout(check, 20);
        };
        check();
      });
    },
  };
}

function sendKeys(ws, str) {
  ws.send(Buffer.from(str, 'utf8'), { binary: true });
}

test('ticket requires auth', async () => {
  const { default: request } = await import('supertest');
  const res = await request(app).post('/api/terminal/ticket').send({ serverId: '11111111-1111-1111-1111-111111111111' });
  assert.equal(res.status, 401);
});

test('ticket rejects another user serverId', async () => {
  const a = await createOwnedServer();
  const b = await registerUser();
  const res = await api(b.token).post('/api/terminal/ticket', { serverId: a.id });
  assert.equal(res.status, 404);
});

test('ticket is issued then single-use over websocket', async () => {
  const { owner, id } = await createOwnedServer();
  const issued = await api(owner.token).post('/api/terminal/ticket', { serverId: id });
  assert.equal(issued.status, 200);
  assert.equal(issued.body.ok, true);
  assert.equal(issued.body.data.expiresIn, 30);
  const ticket = issued.body.data.ticket;
  assert.ok(ticket);

  const server = await listenApp();
  try {
    const ws = await openWs(wsUrl(server, ticket));
    const bag = collect(ws);
    await bag.waitFor((_t, c) => c.some((m) => m.type === 'status' && m.state === 'connected'));
    sendKeys(ws, 'whoami\r');
    await bag.waitFor((t) => t.includes('ubuntu'));
    ws.close();

    await assert.rejects(() => openWs(wsUrl(server, ticket)), (err) => err.statusCode === 401);
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test('websocket without ticket is rejected', async () => {
  const server = await listenApp();
  try {
    const { port } = server.address();
    await assert.rejects(
      () => openWs(`ws://127.0.0.1:${port}/ws/terminal`),
      (err) => err.statusCode === 401,
    );
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test('resize is applied and echo $COLUMNS matches', async () => {
  const { owner, id } = await createOwnedServer();
  const issued = await api(owner.token).post('/api/terminal/ticket', { serverId: id });
  const server = await listenApp();
  try {
    const ws = await openWs(wsUrl(server, issued.body.data.ticket));
    const bag = collect(ws);
    await bag.waitFor((_t, c) => c.some((m) => m.state === 'connected'));
    ws.send(JSON.stringify({ type: 'resize', cols: 120, rows: 40 }));
    sendKeys(ws, 'echo $COLUMNS\r');
    await bag.waitFor((t) => t.includes('120'));
    ws.close();
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test('malformed resize is ignored and session stays up', async () => {
  const { owner, id } = await createOwnedServer();
  const issued = await api(owner.token).post('/api/terminal/ticket', { serverId: id });
  const server = await listenApp();
  try {
    const ws = await openWs(wsUrl(server, issued.body.data.ticket));
    const bag = collect(ws);
    await bag.waitFor((_t, c) => c.some((m) => m.state === 'connected'));
    ws.send(JSON.stringify({ type: 'resize', cols: 9999, rows: 24 }));
    sendKeys(ws, 'whoami\r');
    await bag.waitFor((t) => t.includes('ubuntu'));
    ws.close();
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test('fourth terminal on the same server is refused', async () => {
  const { owner, id } = await createOwnedServer();
  const server = await listenApp();
  const sockets = [];
  try {
    for (let i = 0; i < 3; i += 1) {
      const issued = await api(owner.token).post('/api/terminal/ticket', { serverId: id });
      const ws = await openWs(wsUrl(server, issued.body.data.ticket));
      const bag = collect(ws);
      await bag.waitFor((_t, c) => c.some((m) => m.state === 'connected'));
      sockets.push(ws);
    }
    const fourth = await api(owner.token).post('/api/terminal/ticket', { serverId: id });
    const ws = await openWs(wsUrl(server, fourth.body.data.ticket));
    const bag = collect(ws);
    await bag.waitFor((_t, c) => c.some((m) => m.code === 'SESSION_LIMIT'));
    ws.close();
  } finally {
    for (const s of sockets) s.close();
    await new Promise((r) => server.close(r));
  }
});

test('open/close cycles return activeSessions to 0', async () => {
  const { owner, id } = await createOwnedServer();
  const server = await listenApp();
  try {
    for (let i = 0; i < 10; i += 1) {
      const issued = await api(owner.token).post('/api/terminal/ticket', { serverId: id });
      assert.equal(issued.status, 200, JSON.stringify(issued.body));
      const ws = await openWs(wsUrl(server, issued.body.data.ticket));
      const bag = collect(ws);
      await bag.waitFor((_t, c) => c.some((m) => m.state === 'connected'));
      const entry = inspectPoolForTests(owner.user.id, id);
      assert.equal(entry.activeSessions, 1);
      await new Promise((resolve) => {
        ws.once('close', resolve);
        ws.close();
      });
      const deadline = Date.now() + 1000;
      while (Date.now() < deadline) {
        const after = inspectPoolForTests(owner.user.id, id);
        if ((after?.activeSessions ?? 0) === 0) break;
        await new Promise((r) => setTimeout(r, 20));
      }
      assert.equal(inspectPoolForTests(owner.user.id, id).activeSessions, 0);
    }
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test('terminal pins the pool; files still work; unpin allows eviction', async () => {
  const { owner, id } = await createOwnedServer();
  setIdleTimeoutForTests(80);

  await pinSession(owner.user.id, id);
  assert.equal(inspectPoolForTests(owner.user.id, id).activeSessions, 1);

  const listed = await withSftp(owner.user.id, id, async ({ sftp }) => {
    assert.ok(sftp);
    return 'ok';
  });
  assert.equal(listed, 'ok');
  assert.equal(inspectPoolForTests(owner.user.id, id).refCount, 0);
  assert.equal(inspectPoolForTests(owner.user.id, id).activeSessions, 1);

  await new Promise((r) => setTimeout(r, 160));
  assert.ok(inspectPoolForTests(owner.user.id, id), 'connection must survive idle while pinned');

  unpinSession(owner.user.id, id);
  assert.equal(inspectPoolForTests(owner.user.id, id).activeSessions, 0);
  await new Promise((r) => setTimeout(r, 160));
  assert.equal(inspectPoolForTests(owner.user.id, id), null);
  assert.equal(poolSize(), 0);
});

test('files listing still works with no terminal open', async () => {
  const { owner, id } = await createOwnedServer();
  const res = await api(owner.token).get(`/api/servers/${id}/files?path=/home/ubuntu`);
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
});

test('scripts CRUD is user-scoped', async () => {
  const owner = await registerUser();
  const other = await registerUser();
  const created = await api(owner.token).post('/api/scripts', {
    name: 'list-dir',
    body: 'ls {{path}}',
    tags: ['ops'],
    color: '#58a6ff',
  });
  assert.equal(created.status, 201);
  const id = created.body.data.id;

  const listed = await api(owner.token).get('/api/scripts');
  assert.equal(listed.body.data.length, 1);

  const foreignList = await api(other.token).get('/api/scripts');
  assert.equal(foreignList.body.data.length, 0);

  const foreignGet = await api(other.token).patch(`/api/scripts/${id}`, { name: 'hacked' });
  assert.equal(foreignGet.status, 404);

  const run = await api(owner.token).post(`/api/scripts/${id}/run`);
  assert.equal(run.status, 200);
  assert.equal(run.body.data.runCount, 1);

  const del = await api(owner.token).delete(`/api/scripts/${id}`);
  assert.equal(del.status, 200);
});

process.env.MOCK_SSH = prevMock;
