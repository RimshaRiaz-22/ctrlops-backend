import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hardeningScore, gradeFromScore, coverageLine } from '../../src/services/audits/scoring.js';

test('hardeningScore: all pass → 100', () => {
  assert.equal(
    hardeningScore([
      { status: 'PASS', weight: 8 },
      { status: 'PASS', weight: 2 },
    ]),
    100,
  );
});

test('hardeningScore: all fail → 0', () => {
  assert.equal(
    hardeningScore([
      { status: 'FAIL', weight: 5 },
      { status: 'FAIL', weight: 5 },
    ]),
    0,
  );
});

test('hardeningScore: warnings count half', () => {
  assert.equal(
    hardeningScore([
      { status: 'PASS', weight: 5 },
      { status: 'WARNING', weight: 5 },
    ]),
    75,
  );
});

test('hardeningScore: skips excluded; empty → null', () => {
  assert.equal(
    hardeningScore([
      { status: 'SKIP', weight: 10 },
      { status: 'ERROR', weight: 10 },
    ]),
    null,
  );
  assert.equal(hardeningScore([]), null);
});

test('gradeFromScore bands and CRITICAL cap', () => {
  assert.equal(gradeFromScore(95), 'A');
  assert.equal(gradeFromScore(80), 'B');
  assert.equal(gradeFromScore(65), 'C');
  assert.equal(gradeFromScore(50), 'D');
  assert.equal(gradeFromScore(10), 'F');
  assert.equal(gradeFromScore(null), null);
  assert.equal(
    gradeFromScore(95, [{ severity: 'CRITICAL', status: 'FAIL' }]),
    'C',
  );
  assert.equal(
    gradeFromScore(50, [{ severity: 'CRITICAL', status: 'FAIL' }]),
    'D',
  );
});

test('coverageLine', () => {
  assert.match(
    coverageLine({ auditIds: ['a', 'b'], progress: { completedAuditIds: ['a'] } }),
    /1 of 2/,
  );
});
