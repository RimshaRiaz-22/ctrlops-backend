import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encrypt, decrypt } from '../../src/services/crypto.service.js';

test('encrypt then decrypt round-trips plaintext', () => {
  const plaintext = '-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----';
  const enc = encrypt(plaintext);
  assert.equal(decrypt(enc), plaintext);
});

test('each encryption uses a unique IV', () => {
  const a = encrypt('same-payload');
  const b = encrypt('same-payload');
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.ciphertext, b.ciphertext);
});

test('stores keyVersion on every credential', () => {
  const enc = encrypt('key-material');
  assert.equal(enc.keyVersion, 1);
  assert.ok(enc.authTag);
  assert.ok(enc.ciphertext);
});

test('tampered auth tag throws instead of returning garbage', () => {
  const enc = encrypt('secret-key');
  const tampered = { ...enc, authTag: Buffer.alloc(16).toString('base64') };
  assert.throws(() => decrypt(tampered));
});

test('tampered ciphertext throws', () => {
  const enc = encrypt('secret-key');
  const buf = Buffer.from(enc.ciphertext, 'base64');
  buf[0] ^= 0xff;
  const tampered = { ...enc, ciphertext: buf.toString('base64') };
  assert.throws(() => decrypt(tampered));
});
