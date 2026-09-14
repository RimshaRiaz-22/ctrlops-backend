/**
 * Parse batched audit output delimited by ===CHECK:id=== / ===EXIT:n=== / ===DONE===
 */
export function parseBatch(raw) {
  const text = String(raw ?? '');
  if (!text.includes('===DONE===')) {
    return { ok: false, error: 'Missing ===DONE=== marker', checks: {} };
  }

  const checks = {};
  const checkRe = /===CHECK:([^=\n]+)===\n?([\s\S]*?)===EXIT:(\d+)===/g;
  let m;
  while ((m = checkRe.exec(text)) !== null) {
    const id = m[1].trim();
    checks[id] = {
      stdout: m[2] ?? '',
      stderr: '',
      exitCode: Number(m[3]),
    };
  }

  return { ok: true, checks };
}

export function parseApplicabilityBatch(raw) {
  const text = String(raw ?? '');
  const results = {};
  const re = /===APP:([^=\n]+)===\n?([\s\S]*?)(?=\n===APP:|\n===DONE===|$)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    results[m[1].trim()] = (m[2] ?? '').trim();
  }
  return results;
}

export function section(raw, name) {
  const text = String(raw ?? '');
  const start = `===${name}===`;
  const idx = text.indexOf(start);
  if (idx < 0) return '';
  const after = text.slice(idx + start.length);
  const next = after.search(/\n===/);
  const body = next < 0 ? after : after.slice(0, next);
  return body.replace(/^\n/, '');
}
