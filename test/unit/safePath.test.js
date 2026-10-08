import { test } from 'node:test';
import assert from 'node:assert/strict';
import { safePath, buildBreadcrumbs, parentPath } from '../../src/utils/safePath.js';
import { AppError } from '../../src/middleware/errorHandler.js';

function throwsCode(fn, code) {
  assert.throws(fn, (err) => err instanceof AppError && err.code === code);
}

test('safePath accepts an absolute path', () => {
  assert.equal(safePath('/home/ubuntu'), '/home/ubuntu');
});

test('safePath normalizes ..', () => {
  assert.equal(safePath('/etc/../etc/shadow'), '/etc/shadow');
});

test('safePath rejects relative paths', () => {
  throwsCode(() => safePath('home/ubuntu'), 'PATH_MUST_BE_ABSOLUTE');
});

test('safePath rejects null bytes', () => {
  throwsCode(() => safePath('/tmp/\0x'), 'INVALID_PATH');
});

test('safePath rejects empty', () => {
  throwsCode(() => safePath(''), 'INVALID_PATH');
});

test('safePath rejects over 4096 chars', () => {
  throwsCode(() => safePath(`/${'a'.repeat(4096)}`), 'PATH_TOO_LONG');
});

test('breadcrumbs include Root', () => {
  const crumbs = buildBreadcrumbs('/home/ubuntu');
  assert.deepEqual(crumbs.map((c) => c.path), ['/', '/home', '/home/ubuntu']);
  assert.equal(crumbs[0].label, 'Root');
});

test('parentPath of / is null', () => {
  assert.equal(parentPath('/'), null);
  assert.equal(parentPath('/home/ubuntu'), '/home');
});
