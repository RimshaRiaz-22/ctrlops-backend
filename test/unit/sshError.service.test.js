import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mapSshError, sshErrorToAppError } from '../../src/services/sshError.service.js';

test('handshake timeout becomes a TIMEOUT AppError', () => {
  const mapped = sshErrorToAppError({ message: 'Timed out while waiting for handshake' });
  assert.equal(mapped.code, 'TIMEOUT');
  assert.equal(mapped.statusCode, 504);
  assert.match(mapped.message, /Couldn't reach the host/);
});

const cases = [
  {
    name: 'public key supplied',
    err: { message: 'public key provided' },
    code: 'PUBLIC_KEY_SUPPLIED',
  },
  {
    name: 'key parse error',
    err: { message: 'Cannot parse privateKey: Unsupported key format' },
    code: 'KEY_PARSE_ERROR',
  },
  {
    name: 'passphrase required',
    err: { message: 'Encrypted private key detected, but no passphrase given' },
    code: 'PASSPHRASE_REQUIRED',
  },
  {
    name: 'wrong passphrase',
    err: { message: 'Integrity check failed: incorrect passphrase' },
    code: 'PASSPHRASE_WRONG',
  },
  {
    name: 'host key mismatch',
    err: { code: 'HOST_KEY_MISMATCH', message: 'Host key verification failed: mismatch' },
    code: 'HOST_KEY_MISMATCH',
  },
  {
    name: 'connection refused',
    err: { code: 'ECONNREFUSED', message: 'connect ECONNREFUSED' },
    code: 'CONNECTION_REFUSED',
  },
  {
    name: 'timeout',
    err: { message: 'Timed out while waiting for handshake' },
    code: 'TIMEOUT',
  },
  {
    name: 'host not found',
    err: { code: 'ENOTFOUND', message: 'getaddrinfo ENOTFOUND' },
    code: 'HOST_NOT_FOUND',
  },
  {
    name: 'auth failed',
    err: { message: 'All configured authentication methods failed' },
    code: 'AUTH_FAILED',
  },
  {
    name: 'unknown fallback',
    err: { message: 'something unexpected' },
    code: 'UNKNOWN',
  },
];

for (const row of cases) {
  test(`maps ${row.name} to ${row.code}`, () => {
    const mapped = mapSshError(row.err);
    assert.equal(mapped.code, row.code);
    assert.ok(mapped.message);
  });
}
