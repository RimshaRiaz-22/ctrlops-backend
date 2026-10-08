export function parseControlMessage(raw) {
  if (typeof raw !== 'string' && !Buffer.isBuffer(raw)) {
    return { ok: false };
  }
  const text = typeof raw === 'string' ? raw : raw.toString('utf8');
  let msg;
  try {
    msg = JSON.parse(text);
  } catch {
    return { ok: false };
  }
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
    return { ok: false };
  }
  if (msg.type === 'ping') {
    return { ok: true, type: 'ping' };
  }
  if (msg.type === 'resize') {
    const cols = msg.cols;
    const rows = msg.rows;
    if (!Number.isInteger(cols) || !Number.isInteger(rows)) {
      return { ok: false };
    }
    if (cols < 1 || cols > 1000 || rows < 1 || rows > 1000) {
      return { ok: false };
    }
    return { ok: true, type: 'resize', cols, rows };
  }
  return { ok: false };
}
