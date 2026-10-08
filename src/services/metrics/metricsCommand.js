export const SAMPLE_WINDOW_SEC = '0.2';
export const SAMPLE_WINDOW_MS = 200;

const BODY = [
  'echo "===CPU==="',
  'head -1 /proc/stat',
  'echo "===MEM==="',
  `grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached):' /proc/meminfo`,
  'echo "===SWAP==="',
  'grep -E "^Swap(Total|Free):" /proc/meminfo',
  'echo "===DISK==="',
  'df -B1 --output=source,size,used,avail,pcent,target -x tmpfs -x devtmpfs -x squashfs 2>/dev/null',
  'echo "===NET==="',
  'cat /proc/net/dev',
  'echo "===LOAD==="',
  'cat /proc/loadavg',
  'echo "===UP==="',
  'cat /proc/uptime',
  'echo "===CORES==="',
  'nproc',
  'echo "===PROC==="',
  'ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu 2>/dev/null | head -16',
  'echo "===END==="',
].join('; ');

const BURST_PREFIX = [
  'echo "===CPU0==="',
  'head -1 /proc/stat',
  'echo "===NET0==="',
  'cat /proc/net/dev',
  `sleep ${SAMPLE_WINDOW_SEC}`,
].join('; ');

/** Steady poll: one read, delta vs previous sample. */
export const METRICS_COMMAND = BODY;

/** First poll: two /proc reads 200ms apart so CPU/net are ready on first paint. */
export const METRICS_COMMAND_BURST = `${BURST_PREFIX}; ${BODY}`;
