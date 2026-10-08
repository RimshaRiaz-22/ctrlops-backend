import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shellQuote } from '../../src/utils/shellQuote.js';

test('shellQuote wraps spaces', () => {
  assert.equal(shellQuote('my file.txt'), `'my file.txt'`);
});

test('shellQuote escapes single quotes', () => {
  assert.equal(shellQuote(`it's`), `'it'\\''s'`);
});

test('shellQuote keeps semicolon literal', () => {
  assert.equal(shellQuote('test; rm -rf /tmp/x.zip'), `'test; rm -rf /tmp/x.zip'`);
});

test('shellQuote keeps backticks', () => {
  assert.equal(shellQuote('`whoami`.zip'), `'` + '`whoami`.zip' + `'`);
});

test('shellQuote keeps $()', () => {
  assert.equal(shellQuote('$(whoami).txt'), `'$(whoami).txt'`);
});

test('shellQuote keeps newline', () => {
  assert.equal(shellQuote('a\nb'), `'a\nb'`);
});

test('shellQuote keeps unicode', () => {
  assert.equal(shellQuote('файл.txt'), `'файл.txt'`);
});

test('shellQuote empty string', () => {
  assert.equal(shellQuote(''), `''`);
});
