import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MetricsCoordinator } from '../../src/services/metrics/metricsCoordinator.js';
import { parseMetrics } from '../../src/services/metrics/metricsParser.js';
import {
  buildMockMetricsOutput,
  resetMockMetricsTick,
} from '../../src/services/metrics/mockMetricsOutput.js';

function fakeWs() {
  const messages = [];
  return {
    userId: 'u1',
    readyState: 1,
    OPEN: 1,
    messages,
    send(data) {
      messages.push(JSON.parse(data));
    },
  };
}

function fakePool() {
  const entry = { conn: {}, activeMonitors: 0 };
  return {
    entry,
    pins: 0,
    unpins: 0,
    async pinMonitor() {
      this.pins += 1;
      entry.activeMonitors += 1;
      return entry;
    },
    unpinMonitor() {
      this.unpins += 1;
      entry.activeMonitors = Math.max(0, entry.activeMonitors - 1);
    },
    peek() {
      return entry.activeMonitors > 0 ? entry : null;
    },
  };
}

function rawCollect() {
  return parseMetrics(buildMockMetricsOutput());
}

test('first subscriber pins and starts one loop; second gets cache', async () => {
  resetMockMetricsTick();
  const pool = fakePool();
  const snapshots = [];
  const c = new MetricsCoordinator({
    pool,
    collect: rawCollect,
    writeSnapshot: async (id, s) => snapshots.push({ id, s }),
    intervalMs: 60_000,
    snapshotMinMs: 0,
  });
  const a = fakeWs();
  const b = fakeWs();
  await c.subscribe('s1', 'u1', a);
  assert.equal(pool.pins, 1);
  assert.equal(c.activeLoopCount(), 1);
  const execAfterFirst = [...c.monitors.values()][0].execCount;
  assert.equal(execAfterFirst, 1);
  assert.ok(a.messages.some((m) => m.type === 'monitor:sample'));

  await c.subscribe('s1', 'u1', b);
  assert.equal(pool.pins, 1);
  assert.equal([...c.monitors.values()][0].execCount, 1);
  assert.ok(b.messages.some((m) => m.type === 'monitor:sample'));

  c.unsubscribe('s1', a);
  assert.equal(c.activeLoopCount(), 1);
  c.unsubscribe('s1', b);
  assert.equal(c.activeLoopCount(), 0);
  assert.equal(pool.unpins, 1);
});

test('inFlight skip does not stack exec', async () => {
  resetMockMetricsTick();
  const pool = fakePool();
  let started = 0;
  let finish;
  const collect = () => {
    started += 1;
    if (started === 1) return rawCollect();
    return new Promise((resolve) => {
      finish = resolve;
    });
  };
  const c = new MetricsCoordinator({
    pool,
    collect,
    writeSnapshot: async () => {},
    intervalMs: 60_000,
    snapshotMinMs: 999_999,
  });
  const ws = fakeWs();
  await c.subscribe('s1', 'u1', ws);
  const key = [...c.monitors.keys()][0];
  const p1 = c.poll(key);
  const p2 = c.poll(key);
  finish(rawCollect());
  await p1;
  await p2;
  assert.equal(started, 2);
  c.removeSocket(ws);
});

test('three collect failures stop the loop and unpin', async () => {
  const pool = fakePool();
  const c = new MetricsCoordinator({
    pool,
    collect: async () => {
      throw new Error('down');
    },
    writeSnapshot: async () => {},
    intervalMs: 60_000,
    snapshotMinMs: 999_999,
  });
  const ws = fakeWs();
  await c.subscribe('s1', 'u1', ws);
  const key = 'u1:s1';
  await c.poll(key);
  await c.poll(key);
  assert.ok(ws.messages.some((m) => m.type === 'monitor:status' && m.state === 'unreachable'));
  assert.equal(c.activeLoopCount(), 0);
  assert.equal(pool.unpins, 1);
});

test('snapshot writes at most once per throttle window', async () => {
  resetMockMetricsTick();
  const pool = fakePool();
  const snapshots = [];
  const c = new MetricsCoordinator({
    pool,
    collect: rawCollect,
    writeSnapshot: async (id, s) => snapshots.push(s.status),
    intervalMs: 60_000,
    snapshotMinMs: 60_000,
  });
  const ws = fakeWs();
  await c.subscribe('s1', 'u1', ws);
  const key = [...c.monitors.keys()][0];
  await c.poll(key);
  await c.poll(key);
  assert.ok(snapshots.length <= 1);
  c.removeSocket(ws);
});
