const REDACT = [
  /(password\s*=\s*)\S+/gi,
  /(secret\s*=\s*)\S+/gi,
  /(api[_-]?key\s*=\s*)\S+/gi,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\$[0-9a-zA-Z]\$[^\s:]+/gi,
];

export function sanitiseEvidence(raw) {
  if (raw == null) return null;
  let out = String(raw).slice(0, 500);
  for (const p of REDACT) {
    out = out.replace(p, (match, g1) => {
      if (typeof g1 === 'string') return `${g1}[REDACTED]`;
      return '[REDACTED]';
    });
  }
  return out;
}
