function section(out, name) {
  const tag = `===${name}===`;
  const start = out.indexOf(tag);
  if (start < 0) return '';
  const after = out.indexOf('\n', start);
  const bodyStart = after < 0 ? start + tag.length : after + 1;
  const next = out.indexOf('===', bodyStart);
  return (next < 0 ? out.slice(bodyStart) : out.slice(bodyStart, next)).trim();
}

export function parseCpuRaw(line) {
  const [, ...fields] = line.trim().split(/\s+/);
  const [user, nice, system, idle, iowait, irq, softirq, steal] = fields.map(Number);
  return {
    user: user || 0,
    nice: nice || 0,
    system: system || 0,
    idle: idle || 0,
    iowait: iowait || 0,
    irq: irq || 0,
    softirq: softirq || 0,
    steal: steal || 0,
  };
}

export function cpuPercent(prev, curr) {
  if (!prev) return null;

  const total = (s) =>
    s.user + s.nice + s.system + s.idle + s.iowait + s.irq + s.softirq + s.steal;

  const totalDelta = total(curr) - total(prev);
  const idleDelta = curr.idle + curr.iowait - (prev.idle + prev.iowait);

  if (totalDelta <= 0) return null;
  return Math.min(100, Math.max(0, ((totalDelta - idleDelta) / totalDelta) * 100));
}

export function parseMemory(memBlock, swapBlock) {
  const kv = {};
  for (const line of String(memBlock ?? '').split('\n')) {
    const m = line.match(/^(\w+):\s+(\d+)\s+kB/);
    if (m) kv[m[1]] = Number(m[2]) * 1024;
  }

  const total = kv.MemTotal ?? 0;
  const available = kv.MemAvailable ?? kv.MemFree ?? 0;
  const used = Math.max(0, total - available);

  const swap = {};
  for (const line of String(swapBlock ?? '').split('\n')) {
    const m = line.match(/^Swap(Total|Free):\s+(\d+)\s+kB/);
    if (m) swap[m[1]] = Number(m[2]) * 1024;
  }

  return {
    total,
    used,
    available,
    percent: total ? (used / total) * 100 : 0,
    swapTotal: swap.Total ?? 0,
    swapUsed: Math.max(0, (swap.Total ?? 0) - (swap.Free ?? 0)),
  };
}

export function parseDisks(block) {
  return String(block ?? '')
    .split('\n')
    .slice(1)
    .map((l) => l.trim().split(/\s+/))
    .filter((p) => p.length >= 6)
    .map(([device, size, used, avail, pcent, ...mountParts]) => ({
      device,
      mount: mountParts.join(' ') || '/',
      total: Number(size),
      used: Number(used),
      available: Number(avail),
      percent: Number(String(pcent).replace('%', '')),
    }))
    .filter(
      (d) =>
        d.total > 0 &&
        Number.isFinite(d.percent) &&
        !d.mount.startsWith('/snap/') &&
        d.device !== 'tmpfs' &&
        d.device !== 'devtmpfs',
    );
}

export function parseNetDev(block) {
  const ifaces = {};
  for (const line of String(block ?? '').split('\n')) {
    const m = line.match(/^\s*([^:]+):\s*(.*)$/);
    if (!m) continue;
    const parts = m[2].trim().split(/\s+/).map(Number);
    if (parts.length < 9 || !Number.isFinite(parts[0])) continue;
    ifaces[m[1].trim()] = { rx: parts[0], tx: parts[8] };
  }
  return ifaces;
}

export function networkThroughput(prevIfaces, currIfaces, elapsedMs) {
  if (!prevIfaces || elapsedMs <= 0) return null;

  const seconds = elapsedMs / 1000;
  const result = [];

  for (const [iface, curr] of Object.entries(currIfaces ?? {})) {
    if (iface === 'lo') continue;
    if (/^(docker|veth|br-|virbr)/.test(iface)) continue;

    const prev = prevIfaces[iface];
    if (!prev) continue;

    const rxDelta = curr.rx - prev.rx;
    const txDelta = curr.tx - prev.tx;
    if (rxDelta < 0 || txDelta < 0) continue;

    result.push({
      iface,
      rxBytesPerSec: Math.round(rxDelta / seconds),
      txBytesPerSec: Math.round(txDelta / seconds),
    });
  }
  return result;
}

export function parseUptime(block) {
  return Math.floor(Number(String(block ?? '').trim().split(/\s+/)[0]) || 0);
}

export function parseLoad(block) {
  const [one, five, fifteen] = String(block ?? '')
    .trim()
    .split(/\s+/)
    .map(Number);
  return { '1m': one || 0, '5m': five || 0, '15m': fifteen || 0 };
}

export function parseProcesses(block) {
  return String(block ?? '')
    .split('\n')
    .slice(1)
    .map((l) => l.trim().split(/\s+/))
    .filter((p) => p.length >= 5)
    .map(([pid, user, cpu, mem, ...cmd]) => ({
      pid: Number(pid),
      user,
      cpu: Number(cpu),
      mem: Number(mem),
      command: cmd.join(' '),
    }));
}

export function parseCores(block) {
  const n = Number(String(block ?? '').trim().split(/\s+/)[0]);
  return Number.isFinite(n) && n > 0 ? n : null;
}

export function parseMetrics(out) {
  if (!String(out ?? '').includes('===END===')) {
    const err = new Error('TRUNCATED');
    err.code = 'TRUNCATED';
    throw err;
  }

  return {
    cpu0: section(out, 'CPU0') ? parseCpuRaw(section(out, 'CPU0')) : null,
    cpu: parseCpuRaw(section(out, 'CPU')),
    memory: parseMemory(section(out, 'MEM'), section(out, 'SWAP')),
    disks: parseDisks(section(out, 'DISK')),
    net0: section(out, 'NET0') ? parseNetDev(section(out, 'NET0')) : null,
    net: parseNetDev(section(out, 'NET')),
    load: parseLoad(section(out, 'LOAD')),
    uptimeSeconds: parseUptime(section(out, 'UP')),
    cores: parseCores(section(out, 'CORES')),
    processes: parseProcesses(section(out, 'PROC')),
  };
}

export function computeStatus({ cpu, memory, disks }) {
  const worstDisk = Math.max(0, ...(disks ?? []).map((d) => d.percent));
  const cpuPct = cpu?.percent;
  const memPct = memory?.percent ?? 0;

  if (cpuPct == null) return 'UNKNOWN';
  if (cpuPct > 95 || memPct > 95 || worstDisk > 95) return 'CRITICAL';
  if (cpuPct > 80 || memPct > 85 || worstDisk > 85) return 'WARNING';
  return 'HEALTHY';
}

export function buildSample(serverId, raw, prev, elapsedMs, timestamp = Date.now()) {
  const cpuPct = cpuPercent(prev?.cpu ?? raw.cpu0, raw.cpu);
  const netElapsed = prev?.net ? elapsedMs : raw.net0 ? 200 : elapsedMs;
  const network = networkThroughput(prev?.net ?? raw.net0, raw.net, netElapsed);
  const sample = {
    type: 'monitor:sample',
    serverId,
    timestamp,
    cpu: { percent: cpuPct, cores: raw.cores },
    memory: raw.memory,
    disks: raw.disks,
    network,
    load: raw.load,
    uptimeSeconds: raw.uptimeSeconds,
    processes: raw.processes,
  };
  sample.status = computeStatus(sample);
  return sample;
}
