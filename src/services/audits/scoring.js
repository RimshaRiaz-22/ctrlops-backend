/**
 * Hardening score: PASS = full weight, WARNING = half, FAIL = none.
 * SKIP/ERROR excluded from denominator. null when nothing scored.
 */
export function hardeningScore(findings = []) {
  let earned = 0;
  let total = 0;
  for (const f of findings) {
    if (f.status !== 'PASS' && f.status !== 'WARNING' && f.status !== 'FAIL') continue;
    const w = Number(f.weight) || 0;
    if (w <= 0) continue;
    total += w;
    if (f.status === 'PASS') earned += w;
    else if (f.status === 'WARNING') earned += w / 2;
  }
  if (total === 0) return null;
  return Math.round((earned / total) * 100);
}

const GRADE_ORDER = ['A', 'B', 'C', 'D', 'F'];

export function gradeFromScore(score, findings = []) {
  if (score == null) return null;
  let grade;
  if (score >= 90) grade = 'A';
  else if (score >= 75) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 40) grade = 'D';
  else grade = 'F';

  const criticalFail = findings.some(
    (f) => f.severity === 'CRITICAL' && f.status === 'FAIL',
  );
  if (criticalFail && GRADE_ORDER.indexOf(grade) < GRADE_ORDER.indexOf('C')) {
    grade = 'C';
  }
  return grade;
}

export function countByStatus(findings = []) {
  const counts = { passed: 0, warnings: 0, failed: 0, skipped: 0, errored: 0 };
  for (const f of findings) {
    if (f.status === 'PASS') counts.passed += 1;
    else if (f.status === 'WARNING') counts.warnings += 1;
    else if (f.status === 'FAIL') counts.failed += 1;
    else if (f.status === 'SKIP') counts.skipped += 1;
    else if (f.status === 'ERROR') counts.errored += 1;
  }
  return counts;
}

export function coverageLine(run) {
  const requested = run.auditIds?.length ?? 0;
  const completed = run.progress?.completedAuditIds?.length ?? 0;
  const skippedAudits = Math.max(0, requested - completed);
  if (requested === 0) return 'No audits selected.';
  if (skippedAudits === 0) {
    return `${completed} of ${requested} audits ran fully.`;
  }
  return `${completed} of ${requested} audits ran fully; ${skippedAudits} incomplete or skipped.`;
}
