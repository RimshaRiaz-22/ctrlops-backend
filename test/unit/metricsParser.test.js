import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  parseCpuRaw,
  cpuPercent,
  parseMemory,
  parseDisks,
  parseNetDev,
  networkThroughput,
  parseLoad,
  parseUptime,
  parseProcesses,
  parseMetrics,
  computeStatus,
  buildSample,
} from '../../src/services/metrics/metricsParser.js';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/metrics');
const ubuntu = fs.readFileSync(path.join(dir, 'ubuntu-22.txt'), 'utf8');
const oldKernel = fs.readFileSync(path.join(dir, 'no-memavailable.txt'), 'utf8');

test('parseCpuRaw reads 10-field line including steal', () => {
  const c = parseCpuRaw('cpu  334934 372 102835 8422255 10334 0 1288 412 0 0');
  assert.equal(c.user, 334934);
  assert.equal(c.steal, 412);
});

test('parseCpuRaw missing steal is 0', () => {
  const c = parseCpuRaw('cpu  100 0 50 800 10 0 5');
  assert.equal(c.steal, 0);
  assert.equal(c.softirq, 5);
});

test('cpuPercent first sample is null', () => {
  assert.equal(cpuPercent(null, parseCpuRaw('cpu  10 0 0 90 0 0 0 0')), null);
});

test('cpuPercent zero delta is null', () => {
  const s = parseCpuRaw('cpu  10 0 0 90 0 0 0 0');
  assert.equal(cpuPercent(s, s), null);
});

test('cpuPercent counter reset is null', () => {
  const prev = parseCpuRaw('cpu  200 0 0 800 0 0 0 0');
  const curr = parseCpuRaw('cpu  10 0 0 90 0 0 0 0');
  assert.equal(cpuPercent(prev, curr), null);
});

test('cpuPercent fully idle is 0', () => {
  const prev = parseCpuRaw('cpu  0 0 0 100 0 0 0 0');
  const curr = parseCpuRaw('cpu  0 0 0 200 0 0 0 0');
  assert.equal(cpuPercent(prev, curr), 0);
});

test('cpuPercent fully busy is 100', () => {
  const prev = parseCpuRaw('cpu  100 0 0 0 0 0 0 0');
  const curr = parseCpuRaw('cpu  200 0 0 0 0 0 0 0');
  assert.equal(cpuPercent(prev, curr), 100);
});

test('cpuPercent counts steal as non-idle', () => {
  const prev = parseCpuRaw('cpu  0 0 0 0 0 0 0 0');
  const curr = parseCpuRaw('cpu  0 0 0 50 0 0 0 50');
  assert.equal(cpuPercent(prev, curr), 50);
});

test('parseMemory uses MemAvailable not MemFree', () => {
  const mem = parseMemory(
    'MemTotal: 1000 kB\nMemFree: 10 kB\nMemAvailable: 400 kB\n',
    'SwapTotal: 0 kB\nSwapFree: 0 kB\n',
  );
  assert.equal(mem.total, 1000 * 1024);
  assert.equal(mem.used, 600 * 1024);
  assert.equal(mem.percent, 60);
  assert.equal(mem.swapTotal, 0);
});

test('parseMemory falls back to MemFree', () => {
  const mem = parseMemory('MemTotal: 1000 kB\nMemFree: 250 kB\n', '');
  assert.equal(mem.used, 750 * 1024);
});

test('parseMemory swap in use', () => {
  const mem = parseMemory(
    'MemTotal: 1000 kB\nMemAvailable: 500 kB\n',
    'SwapTotal: 200 kB\nSwapFree: 50 kB\n',
  );
  assert.equal(mem.swapTotal, 200 * 1024);
  assert.equal(mem.swapUsed, 150 * 1024);
});

test('parseDisks excludes snaps tmpfs and zero-size', () => {
  const disks = parseDisks(`Filesystem 1B-blocks Used Available Use% Mounted on
/dev/vda1 1000 400 600 40% /
/dev/loop0 100 100 0 100% /snap/core/1
tmpfs 500 0 500 0% /dev/shm
/dev/empty 0 0 0 0% /mnt/empty
`);
  assert.equal(disks.length, 1);
  assert.equal(disks[0].mount, '/');
  assert.equal(disks[0].percent, 40);
});

test('networkThroughput first sample is null', () => {
  assert.equal(networkThroughput(null, { eth0: { rx: 10, tx: 10 } }, 3000), null);
});

test('networkThroughput skips lo docker and wraparound', () => {
  const prev = {
    lo: { rx: 1, tx: 1 },
    eth0: { rx: 1000, tx: 2000 },
    docker0: { rx: 5, tx: 5 },
    eth1: { rx: 9999, tx: 9999 },
  };
  const curr = {
    lo: { rx: 100, tx: 100 },
    eth0: { rx: 4000, tx: 5000 },
    docker0: { rx: 50, tx: 50 },
    eth1: { rx: 10, tx: 10 },
  };
  const rates = networkThroughput(prev, curr, 1000);
  assert.equal(rates.length, 1);
  assert.equal(rates[0].iface, 'eth0');
  assert.equal(rates[0].rxBytesPerSec, 3000);
  assert.equal(rates[0].txBytesPerSec, 3000);
});

test('networkThroughput skips new interface mid-session', () => {
  const rates = networkThroughput({ eth0: { rx: 1, tx: 1 } }, { eth0: { rx: 2, tx: 2 }, eth1: { rx: 9, tx: 9 } }, 1000);
  assert.equal(rates.length, 1);
  assert.equal(rates[0].iface, 'eth0');
});

test('parseLoad parseUptime parseProcesses', () => {
  assert.deepEqual(parseLoad('0.52 0.61 0.48 1/220 1842'), { '1m': 0.52, '5m': 0.61, '15m': 0.48 });
  assert.equal(parseUptime('1847293.41 7231001.88'), 1847293);
  const procs = parseProcesses('PID USER %CPU %MEM COMMAND\n1284 www-data 12.4 3.1 nginx: worker process\n');
  assert.equal(procs[0].command, 'nginx: worker process');
  assert.equal(procs[0].pid, 1284);
});

test('parseMetrics ubuntu fixture', () => {
  const raw = parseMetrics(ubuntu);
  assert.equal(raw.cores, 4);
  assert.equal(raw.memory.percent < 50, true);
  assert.ok(raw.disks.some((d) => d.mount === '/'));
  assert.ok(!raw.disks.some((d) => d.mount.startsWith('/snap/')));
  assert.ok(raw.net.eth0);
  assert.equal(raw.processes[0].command, 'node');
});

test('parseMetrics missing END throws TRUNCATED', () => {
  assert.throws(() => parseMetrics('===CPU===\ncpu  1 0 0 1 0 0 0 0\n'), (err) => err.code === 'TRUNCATED');
});

test('parseMetrics old kernel MemFree fallback and missing nproc', () => {
  const raw = parseMetrics(oldKernel);
  assert.equal(raw.cores, null);
  assert.equal(raw.memory.used, (1000000 - 200000) * 1024);
  assert.equal(raw.memory.swapUsed, 400000 * 1024);
});

test('computeStatus thresholds and worst disk', () => {
  const base = { cpu: { percent: 10 }, memory: { percent: 10 }, disks: [{ percent: 10 }] };
  assert.equal(computeStatus(base), 'HEALTHY');
  assert.equal(computeStatus({ ...base, cpu: { percent: 81 } }), 'WARNING');
  assert.equal(computeStatus({ ...base, memory: { percent: 86 } }), 'WARNING');
  assert.equal(computeStatus({ ...base, disks: [{ percent: 10 }, { percent: 90 }] }), 'WARNING');
  assert.equal(computeStatus({ ...base, cpu: { percent: 96 } }), 'CRITICAL');
  assert.equal(computeStatus({ ...base, disks: [{ percent: 96 }] }), 'CRITICAL');
  assert.equal(computeStatus({ cpu: { percent: null }, memory: { percent: 10 }, disks: [] }), 'UNKNOWN');
});

test('buildSample first cpu is null status UNKNOWN', () => {
  const raw = parseMetrics(ubuntu);
  const sample = buildSample('s1', raw, null, 3000, 1);
  assert.equal(sample.cpu.percent, null);
  assert.equal(sample.network, null);
  assert.equal(sample.status, 'UNKNOWN');
});

test('buildSample uses CPU0/NET0 for first paint', () => {
  const out = `===CPU0===
cpu  100 0 0 900 0 0 0 0
===NET0===
  eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0
===CPU===
cpu  150 0 0 950 0 0 0 0
===MEM===
MemTotal:        1000 kB
MemAvailable:     500 kB
===SWAP===
SwapTotal: 0 kB
SwapFree: 0 kB
===DISK===
Filesystem 1B-blocks Used Available Use% Mounted on
/dev/vda1 1000 400 600 40% /
===NET===
  eth0: 5000 0 0 0 0 0 0 0 6000 0 0 0 0 0 0 0
===LOAD===
0.1 0.1 0.1
===UP===
10.0 20.0
===CORES===
2
===PROC===
  PID USER %CPU %MEM COMMAND
===END===
`;
  const raw = parseMetrics(out);
  const sample = buildSample('s1', raw, null, 0, 1);
  assert.ok(sample.cpu.percent > 0);
  assert.equal(sample.network[0].rxBytesPerSec, 20000);
});
