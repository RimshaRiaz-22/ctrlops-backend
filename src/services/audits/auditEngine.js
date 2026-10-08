import { acquire, release } from '../sshPool.service.js';
import { logger } from '../../utils/logger.js';
import * as auditRunRepo from '../../repositories/auditRun.repository.js';
import * as auditFindingRepo from '../../repositories/auditFinding.repository.js';
import { getChecksForAudit } from './checks/index.js';
import { getAuditMeta } from './catalog.js';
import { exec as defaultExec } from './exec.js';
import {
  detectEnvironment,
  buildAuditBatch,
  buildApplicabilityBatch,
} from './environment.js';
import { parseBatch, parseApplicabilityBatch } from './parseBatch.js';
import { sanitiseEvidence } from './evidence.js';
import { hardeningScore, gradeFromScore, countByStatus } from './scoring.js';

function toFinding(check, category, status, detail, evidence) {
  return {
    auditId: check.auditId,
    checkId: check.id,
    title: check.title,
    category,
    severity: check.severity,
    status,
    weight: check.weight ?? 1,
    detail: detail ?? null,
    evidence: evidence ? sanitiseEvidence(evidence) : null,
    remediationText: check.remediation?.summary ?? null,
    remediationCommand: check.remediation?.command ?? null,
  };
}

async function safeUpdateProgress(runId, progress) {
  try {
    await auditRunRepo.updateProgress(runId, progress);
    return true;
  } catch (err) {
    if (err?.code === '23503') return false;
    throw err;
  }
}

export async function probeSudo(userId, serverId, { execFn = defaultExec } = {}) {
  const entry = await acquire(userId, serverId);
  try {
    const env = await detectEnvironment(entry.conn, execFn);
    return {
      sudoMode: env.sudoMode,
      family: env.family,
      distro: env.distro,
      version: env.version,
    };
  } finally {
    release(userId, serverId);
  }
}

export async function runAudits(
  { userId, serverId, auditIds, runId },
  { execFn = defaultExec } = {},
) {
  const started = Date.now();
  const completedAuditIds = [];
  const allFindings = [];
  let env = null;

  const entry = await acquire(userId, serverId);
  try {
    env = await detectEnvironment(entry.conn, execFn);
    try {
      await auditRunRepo.setEnv(runId, {
        sudoMode: env.sudoMode,
        osSnapshot: {
          family: env.family,
          distro: env.distro,
          version: env.version,
        },
      });
    } catch (err) {
      if (err?.code === '23503') return;
      throw err;
    }

    for (const auditId of auditIds) {
      const alive = await safeUpdateProgress(runId, {
        currentAuditId: auditId,
        completedAuditIds: [...completedAuditIds],
        message: `Running ${auditId}`,
      });
      if (!alive) return;

      const meta = getAuditMeta(auditId);
      const category = meta?.category ?? 'SERVER';
      const checks = getChecksForAudit(auditId);

      if (!checks?.length) {
        allFindings.push({
          auditId,
          checkId: `${auditId}-unavailable`,
          title: `${meta?.title ?? auditId} not implemented`,
          category,
          severity: 'INFO',
          status: 'SKIP',
          weight: 0,
          detail: 'Check definitions for this audit are not registered yet.',
          evidence: null,
          remediationText: null,
          remediationCommand: null,
        });
        completedAuditIds.push(auditId);
        continue;
      }

      let runnable = [...checks];

      // Sudo-unavailable: skip sudo checks before probes
      if (env.sudoMode === 'UNAVAILABLE') {
        const kept = [];
        for (const c of runnable) {
          if (c.requiresSudo) {
            allFindings.push(
              toFinding(
                c,
                category,
                'SKIP',
                'Skipped: sudo is unavailable for this session.',
                null,
              ),
            );
          } else {
            kept.push(c);
          }
        }
        runnable = kept;
      }

      // Applicability
      if (runnable.length) {
        const appCmd = buildApplicabilityBatch(runnable);
        if (appCmd) {
          try {
            const appOut = await execFn(entry.conn, appCmd, { timeoutMs: 30_000 });
            const appResults = parseApplicabilityBatch(appOut);
            const afterApp = [];
            for (const c of runnable) {
              if (!c.applicability) {
                afterApp.push(c);
                continue;
              }
              const raw = (appResults[c.id] ?? '').trim();
              const expect = c.applicability.expect ?? 'yes';
              if (raw.includes(expect)) {
                afterApp.push(c);
              } else {
                allFindings.push(
                  toFinding(
                    c,
                    category,
                    'SKIP',
                    `Not applicable (probe expected "${expect}", got "${raw || 'empty'}").`,
                    raw,
                  ),
                );
              }
            }
            runnable = afterApp;
          } catch (err) {
            for (const c of runnable) {
              allFindings.push(
                toFinding(c, category, 'ERROR', `Applicability probe failed: ${err.message}`, null),
              );
            }
            runnable = [];
          }
        }
      }

      // Main batch
      if (runnable.length) {
        try {
          const batch = buildAuditBatch(runnable, env);
          const out = await execFn(entry.conn, batch, { timeoutMs: 90_000 });
          const parsed = parseBatch(out);
          for (const c of runnable) {
            if (!parsed.ok) {
              allFindings.push(
                toFinding(c, category, 'ERROR', parsed.error || 'Batch parse failed', out),
              );
              continue;
            }
            const raw = parsed.checks[c.id];
            if (!raw) {
              allFindings.push(
                toFinding(c, category, 'ERROR', 'No output captured for this check.', null),
              );
              continue;
            }
            try {
              const verdict = c.evaluate(raw.stdout, raw.stderr, raw.exitCode, env);
              allFindings.push(
                toFinding(c, category, verdict.status, verdict.detail, raw.stdout),
              );
            } catch (err) {
              allFindings.push(
                toFinding(c, category, 'ERROR', `Evaluation failed: ${err.message}`, raw.stdout),
              );
            }
          }
        } catch (err) {
          for (const c of runnable) {
            allFindings.push(
              toFinding(c, category, 'ERROR', `Audit exec failed: ${err.message}`, null),
            );
          }
        }
      }

      completedAuditIds.push(auditId);
      await safeUpdateProgress(runId, {
        currentAuditId: null,
        completedAuditIds: [...completedAuditIds],
        message: `Finished ${auditId}`,
      });
    }

    const insertResult = await auditFindingRepo.insertMany(runId, allFindings);
    if (insertResult.softFailed) {
      logger.warn({ runId, serverId }, 'Audit findings soft-failed (server likely deleted)');
      return;
    }

    const counts = countByStatus(allFindings);
    const score = hardeningScore(allFindings);
    const grade = gradeFromScore(score, allFindings);
    const hasErrors = counts.errored > 0;
    const allSkipped =
      allFindings.length > 0 &&
      allFindings.every((f) => f.status === 'SKIP' || f.status === 'ERROR');
    const status = hasErrors || allSkipped || completedAuditIds.length < auditIds.length
      ? 'PARTIAL'
      : 'COMPLETED';

    try {
      await auditRunRepo.finishRun(runId, {
        status,
        sudoMode: env.sudoMode,
        score,
        grade,
        totalChecks: allFindings.length,
        ...counts,
        osSnapshot: {
          family: env.family,
          distro: env.distro,
          version: env.version,
        },
        progress: {
          currentAuditId: null,
          completedAuditIds,
          message: 'Done',
        },
        durationMs: Date.now() - started,
      });
    } catch (err) {
      if (err?.code === '23503') {
        logger.warn({ runId }, 'Audit run finish soft-failed (FK)');
        return;
      }
      throw err;
    }
  } catch (err) {
    logger.error({ err, runId }, 'Audit run failed');
    try {
      await auditRunRepo.markFailed(runId, err.message ?? 'Audit run failed');
    } catch {
      /* ignore */
    }
    throw err;
  } finally {
    release(userId, serverId);
  }
}
