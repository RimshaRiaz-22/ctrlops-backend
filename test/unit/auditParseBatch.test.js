import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseBatch, parseApplicabilityBatch, section } from '../../src/services/audits/parseBatch.js';

test('parseBatch extracts checks', () => {
  const raw = [
    '===CHECK:a===',
    'hello',
    '===EXIT:0===',
    '===CHECK:b===',
    'bye',
    '===EXIT:1===',
    '===DONE===',
  ].join('\n');
  const parsed = parseBatch(raw);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.checks.a.stdout.trim(), 'hello');
  assert.equal(parsed.checks.a.exitCode, 0);
  assert.equal(parsed.checks.b.exitCode, 1);
});

test('parseBatch missing DONE', () => {
  const parsed = parseBatch('===CHECK:a===\nx\n===EXIT:0===');
  assert.equal(parsed.ok, false);
});

test('parseApplicabilityBatch', () => {
  const raw = '===APP:c1===\nyes\n===APP:c2===\nno\n===DONE===';
  const r = parseApplicabilityBatch(raw);
  assert.equal(r.c1, 'yes');
  assert.equal(r.c2, 'no');
});

test('section helper', () => {
  const raw = '===OS===\nID=ubuntu\n===SUDO===\nEXIT:0\n===DONE===';
  assert.match(section(raw, 'OS'), /ID=ubuntu/);
  assert.match(section(raw, 'SUDO'), /EXIT:0/);
});
