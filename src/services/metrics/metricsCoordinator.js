import * as sshPool from '../sshPool.service.js';
import * as healthRepo from '../../repositories/healthSnapshot.repository.js';
import { collectSample } from './collectSample.js';
import { buildSample } from './metricsParser.js';

function monitorKey(userId, serverId) {
  return `${userId}:${serverId}`;
}

function send(ws, payload) {
  const open = ws.OPEN ?? 1;
  if (ws.readyState === open) {
    ws.send(typeof payload === 'string' ? payload : JSON.stringify(payload));
  }
}

export class MetricsCoordinator {
  constructor({
    pool = sshPool,
    collect = collectSample,
    writeSnapshot = (serverId, sample) =>
      healthRepo.upsertHealthSnapshot({
        serverId,
        cpuPercent: sample.cpu?.percent,
        memoryPercent: sample.memory?.percent,
        diskPercent: Math.max(0, ...(sample.disks ?? []).map((d) => d.percent)),
        loadAvg1: sample.load?.['1m'],
        uptimeSeconds: sample.uptimeSeconds,
        status: sample.status,
      }),
    intervalMs = 1000,
    snapshotMinMs = 30000,
  } = {}) {
    this.pool = pool;
    this.collect = collect;
    this.writeSnapshot = writeSnapshot;
    this.INTERVAL_MS = intervalMs;
    this.snapshotMinMs = snapshotMinMs;
    this.MAX_FAILURES = 3;
    this.monitors = new Map();
  }

  async subscribe(serverId, userId, ws) {
    const key = monitorKey(userId, serverId);
    let m = this.monitors.get(key);

    if (!m) {
      m = {
        key,
        serverId,
        userId,
        subscribers: new Set(),
        timer: null,
        prevRaw: null,
        prevAt: null,
        lastSample: null,
        inFlight: false,
        failures: 0,
        lastSnapshotAt: 0,
        execCount: 0,
      };
      this.monitors.set(key, m);

      await this.pool.pinMonitor(userId, serverId);
      m.subscribers.add(ws);
      m.timer = setInterval(() => {
        this.poll(key).catch(() => {});
      }, this.INTERVAL_MS);
      m.timer.unref?.();
      await this.poll(key);
      return;
    }

    m.subscribers.add(ws);
    if (m.lastSample) send(ws, m.lastSample);
  }

  unsubscribe(serverId, ws) {
    this.unsubscribeKey(monitorKey(ws.userId, serverId), ws);
  }

  unsubscribeKey(key, ws) {
    const m = this.monitors.get(key);
    if (!m) return;

    m.subscribers.delete(ws);
    if (m.subscribers.size > 0) return;

    clearInterval(m.timer);
    this.monitors.delete(key);
    this.pool.unpinMonitor(m.userId, m.serverId);
  }

  async poll(key) {
    const m = this.monitors.get(key);
    if (!m || m.inFlight) return;

    m.inFlight = true;
    const now = Date.now();

    try {
      let entry = this.pool.peek(m.userId, m.serverId);
      if (!entry?.conn) {
        entry = await this.pool.pinMonitor(m.userId, m.serverId);
      }
      const raw = await this.collect(entry.conn, { burst: !m.prevRaw });
      m.execCount += 1;

      const sample = buildSample(m.serverId, raw, m.prevRaw, now - (m.prevAt ?? now), now);
      m.prevRaw = raw;
      m.prevAt = now;
      m.lastSample = sample;
      m.failures = 0;

      this.broadcast(m, sample);

      if (sample.cpu?.percent != null && now - m.lastSnapshotAt > this.snapshotMinMs) {
        m.lastSnapshotAt = now;
        Promise.resolve(this.writeSnapshot(m.serverId, sample)).catch(() => {});
      }
    } catch {
      m.failures += 1;
      if (m.failures >= this.MAX_FAILURES) {
        clearInterval(m.timer);
        const payload = {
          type: 'monitor:status',
          serverId: m.serverId,
          state: 'unreachable',
          message: 'Lost contact with the server.',
        };
        this.broadcast(m, payload);
        Promise.resolve(
          this.writeSnapshot(m.serverId, {
            cpu: { percent: null },
            memory: { percent: null },
            disks: [],
            load: { '1m': null },
            uptimeSeconds: null,
            status: 'UNREACHABLE',
          }),
        ).catch(() => {});
        this.monitors.delete(key);
        this.pool.unpinMonitor(m.userId, m.serverId);
      }
    } finally {
      if (this.monitors.get(key) === m) m.inFlight = false;
    }
  }

  broadcast(m, payload) {
    const data = JSON.stringify(payload);
    const open = 1;
    for (const ws of m.subscribers) {
      if (ws.readyState === (ws.OPEN ?? open)) ws.send(data);
      else m.subscribers.delete(ws);
    }
  }

  removeSocket(ws) {
    for (const key of [...this.monitors.keys()]) {
      this.unsubscribeKey(key, ws);
    }
  }

  activeLoopCount() {
    return this.monitors.size;
  }
}

export const metricsCoordinator = new MetricsCoordinator();

export function resetCoordinatorForTests() {
  for (const m of metricsCoordinator.monitors.values()) {
    clearInterval(m.timer);
  }
  metricsCoordinator.monitors.clear();
}
