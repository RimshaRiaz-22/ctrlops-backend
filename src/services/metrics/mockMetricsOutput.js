let tick = 0;

export function resetMockMetricsTick() {
  tick = 0;
}

export function buildMockMetricsOutput() {
  tick += 1;
  const user = 1000 + tick * 200;
  const idle = 8000 + tick * 40;
  const rx = 1_000_000 + tick * 125_440;
  const tx = 500_000 + tick * 48_200;
  const memAvail = 4_694_320;
  const user0 = Math.max(0, user - 200);
  const idle0 = Math.max(0, idle - 40);
  const rx0 = Math.max(0, rx - 125_440);
  const tx0 = Math.max(0, tx - 48_200);
  return [
    '===CPU0===',
    `cpu  ${user0} 372 102835 ${idle0} 10334 0 1288 412 0 0`,
    '===NET0===',
    'Inter-|   Receive                                                |  Transmit',
    ' face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed',
    '    lo: 1048576     100    0    0    0     0          0         0  1048576     100    0    0    0     0       0          0',
    `  eth0: ${rx0}    9000    0    0    0     0          0         0   ${tx0}    7000    0    0    0     0       0          0`,
    '===CPU===',
    `cpu  ${user} 372 102835 ${idle} 10334 0 1288 412 0 0`,
    '===MEM===',
    'MemTotal:        8039172 kB',
    'MemFree:          412220 kB',
    `MemAvailable:    ${memAvail} kB`,
    'Buffers:          280112 kB',
    'Cached:          3894016 kB',
    '===SWAP===',
    'SwapTotal:       2097148 kB',
    'SwapFree:        2097148 kB',
    '===DISK===',
    'Filesystem     1B-blocks       Used Available Use% Mounted on',
    '/dev/vda1     53687091200 21474836480 32212254720  40% /',
    '/dev/vdb     536870912000 418759311360 118111600640  78% /data',
    '/dev/loop0       123731968   123731968          0 100% /snap/core/16202',
    '===NET===',
    'Inter-|   Receive                                                |  Transmit',
    ' face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed',
    '    lo: 1048576     100    0    0    0     0          0         0  1048576     100    0    0    0     0       0          0',
    `  eth0: ${rx}    9000    0    0    0     0          0         0   ${tx}    7000    0    0    0     0       0          0`,
    '===LOAD===',
    '0.52 0.61 0.48 1/220 1842',
    '===UP===',
    '1847293.41 7231001.88',
    '===CORES===',
    '4',
    '===PROC===',
    '  PID USER      %CPU %MEM COMMAND',
    ' 1284 www-data  12.4  3.1 node',
    '  892 root       4.1  1.2 sshd',
    '===END===',
    '',
  ].join('\n');
}
