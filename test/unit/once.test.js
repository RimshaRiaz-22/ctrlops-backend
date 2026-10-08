import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from '../../src/utils/once.js';

test('once runs the wrapped function exactly once', () => {
  let n = 0;
  const fn = once(() => {
    n += 1;
    return n;
  });
  assert.equal(fn(), 1);
  assert.equal(fn(), undefined);
  assert.equal(fn(), undefined);
  assert.equal(n, 1);
});

test('cleanup called five times decrements activeSessions exactly once', () => {
  let activeSessions = 1;
  const cleanup = once(() => {
    activeSessions -= 1;
  });
  for (let i = 0; i < 5; i += 1) cleanup();
  assert.equal(activeSessions, 0);
});
