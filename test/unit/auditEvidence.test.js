import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitiseEvidence } from '../../src/services/audits/evidence.js';

test('truncates to 500', () => {
  const out = sanitiseEvidence('x'.repeat(600));
  assert.equal(out.length, 500);
});

test('redacts password and api key', () => {
  assert.match(sanitiseEvidence('password=secret123 more'), /password=\[REDACTED\]/);
  assert.match(sanitiseEvidence('api_key=abcd'), /api_key=\[REDACTED\]/);
});

test('redacts PEM and shadow hash', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----';
  assert.equal(sanitiseEvidence(pem), '[REDACTED]');
  assert.match(sanitiseEvidence('root:$6$saltsalt$hashhere:0:0'), /\[REDACTED\]/);
});
