const SENSITIVE_KEYS = [
  'privatekey',
  'credential',
  'passphrase',
  'password',
  'credciphertext',
  'passciphertext',
  'crediv',
  'passiv',
  'credauthtag',
  'passauthtag',
  'authorization',
  'accesstoken',
  'refreshtoken',
];

const SECRET_PATTERNS = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/i,
  /BEGIN OPENSSH/i,
  /BEGIN RSA PRIVATE KEY/i,
];

function redactString(value) {
  if (typeof value !== 'string') return value;
  if (SECRET_PATTERNS.some((pattern) => pattern.test(value))) return '[REDACTED]';
  return value;
}

function redactValue() {
  return '[REDACTED]';
}

export function redactObject(obj) {
  if (!obj || typeof obj !== 'object') return redactString(obj);
  if (obj instanceof Error) {
    return redactObject({
      name: obj.name,
      message: obj.message,
      stack: obj.stack,
      code: obj.code,
    });
  }
  if (Array.isArray(obj)) return obj.map(redactObject);

  const out = {};
  for (const [key, value] of Object.entries(obj)) {
    if (SENSITIVE_KEYS.some((k) => key.toLowerCase().includes(k))) {
      out[key] = redactValue();
    } else if (value && typeof value === 'object') {
      out[key] = redactObject(value);
    } else {
      out[key] = redactString(value);
    }
  }
  return out;
}

function redactArg(arg) {
  if (arg instanceof Error) return redactObject(arg);
  if (typeof arg === 'string') return redactString(arg);
  if (arg && typeof arg === 'object') return redactObject(arg);
  return arg;
}

export const logger = {
  info: (...args) => console.log(...args.map(redactArg)),
  warn: (...args) => console.warn(...args.map(redactArg)),
  error: (...args) => console.error(...args.map(redactArg)),
};
