import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildDocDefinition, pdfFilename } from '../../src/services/audits/pdfReport.js';

test('buildDocDefinition includes coverage and score', () => {
  const run = {
    score: 70,
    grade: 'C',
    startedAt: new Date().toISOString(),
    auditIds: ['ssh-hardening'],
    progress: { completedAuditIds: ['ssh-hardening'] },
    osSnapshot: { distro: 'Ubuntu' },
  };
  const findings = [
    {
      status: 'FAIL',
      severity: 'HIGH',
      title: 'Root login',
      detail: 'yes',
      remediationText: 'Set no',
    },
    { status: 'PASS', severity: 'LOW', title: 'Ok', detail: 'fine' },
  ];
  const doc = buildDocDefinition(run, findings, { name: 'box', host: '1.2.3.4' });
  assert.ok(doc.content.length > 3);
  assert.match(pdfFilename({ name: 'My Box' }, run), /hardening-My_Box-/);
});

test('large findings list still builds', () => {
  const findings = Array.from({ length: 60 }, (_, i) => ({
    status: i % 5 === 0 ? 'FAIL' : 'PASS',
    severity: 'MEDIUM',
    title: `Check ${i}`,
    detail: `Detail ${i}`,
  }));
  const doc = buildDocDefinition(
    {
      score: 80,
      grade: 'B',
      startedAt: new Date().toISOString(),
      auditIds: ['a'],
      progress: { completedAuditIds: ['a'] },
    },
    findings,
    { name: 's', host: 'h' },
  );
  assert.ok(doc);
});
