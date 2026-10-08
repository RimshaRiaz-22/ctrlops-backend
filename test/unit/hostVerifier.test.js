import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { verifyHostKey } from '../../src/services/ssh.service.js';

function fakeKeyBuffer(label) {
  const algo = Buffer.from('ssh-ed25519');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(algo.length, 0);
  return Buffer.concat([header, algo, crypto.createHash('sha256').update(label).digest()]);
}

test('TOFU accepts the first host key and returns its fingerprint', () => {
  const key = fakeKeyBuffer('first');
  const result = verifyHostKey(null, key);
  assert.equal(result.ok, true);
  assert.equal(result.tofu, true);
  assert.ok(result.fingerprint);
  assert.equal(result.algorithm, 'ssh-ed25519');
});

test('matching stored fingerprint is accepted', () => {
  const key = fakeKeyBuffer('same');
  const first = verifyHostKey(null, key);
  const second = verifyHostKey(first.fingerprint, key);
  assert.equal(second.ok, true);
  assert.equal(second.tofu, false);
});

test('rotated host key is rejected and fingerprint is not replaced', () => {
  const original = fakeKeyBuffer('original');
  const rotated = fakeKeyBuffer('rotated');
  const stored = verifyHostKey(null, original).fingerprint;
  const result = verifyHostKey(stored, rotated);
  assert.equal(result.ok, false);
  assert.notEqual(result.fingerprint, stored);
});
