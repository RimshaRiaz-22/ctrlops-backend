import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactObject } from '../../src/utils/logger.js';

test('redacts credential fields and private key PEM blobs', () => {
  const redacted = redactObject({
    privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----',
    password: 'hunter2',
    credCiphertext: 'abc',
    authorization: 'Bearer secret',
    host: '8.8.8.8',
  });

  assert.equal(redacted.privateKey, '[REDACTED]');
  assert.equal(redacted.password, '[REDACTED]');
  assert.equal(redacted.credCiphertext, '[REDACTED]');
  assert.equal(redacted.authorization, '[REDACTED]');
  assert.equal(redacted.host, '8.8.8.8');
});

test('redacts PEM material inside error messages', () => {
  const err = new Error('failed -----BEGIN RSA PRIVATE KEY----- secret');
  const redacted = redactObject(err);
  assert.equal(redacted.message, '[REDACTED]');
});
