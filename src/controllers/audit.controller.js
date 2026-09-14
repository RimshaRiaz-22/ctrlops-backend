import { AppError } from '../middleware/errorHandler.js';
import * as serverRepo from '../repositories/server.repository.js';
import * as auditRunRepo from '../repositories/auditRun.repository.js';
import * as auditFindingRepo from '../repositories/auditFinding.repository.js';
import { listCatalog } from '../services/audits/catalog.js';
import { implementedAuditIds } from '../services/audits/checks/index.js';
import { probeSudo, runAudits } from '../services/audits/auditEngine.js';
import { buildPdfBuffer, pdfFilename } from '../services/audits/pdfReport.js';
import { coverageLine } from '../services/audits/scoring.js';

export async function catalog(_req, res, next) {
  try {
    res.json({ ok: true, data: listCatalog(implementedAuditIds()) });
  } catch (err) {
    next(err);
  }
}

export async function sudoStatus(req, res, next) {
  try {
    const serverId = req.params.serverId;
    const server = await serverRepo.findOwned(serverId, req.user.id);
    if (!server) throw new AppError('NOT_FOUND', 404, 'Server not found.');
    const data = await probeSudo(req.user.id, serverId);
    res.json({ ok: true, data });
  } catch (err) {
    next(err);
  }
}

export async function startRun(req, res, next) {
  try {
    const serverId = req.params.serverId;
    const { auditIds } = req.body;
    const server = await serverRepo.findOwned(serverId, req.user.id);
    if (!server) throw new AppError('NOT_FOUND', 404, 'Server not found.');

    const existing = await auditRunRepo.findRunningByServer(serverId);
    if (existing) {
      throw new AppError(
        'AUDIT_RUNNING',
        409,
        'An audit is already running on this server.',
        'Wait for it to finish or open it from Reports history.',
      );
    }

    const run = await auditRunRepo.createRunning({
      userId: req.user.id,
      serverId,
      auditIds,
    });

    runAudits({
      userId: req.user.id,
      serverId,
      auditIds,
      runId: run.id,
    }).catch((err) =>
      auditRunRepo.markFailed(run.id, err.message ?? 'Audit run failed'),
    );

    res.status(202).json({
      ok: true,
      data: { runId: run.id, status: 'RUNNING' },
    });
  } catch (err) {
    next(err);
  }
}

export async function listRuns(req, res, next) {
  try {
    const serverId = req.params.serverId;
    const server = await serverRepo.findOwned(serverId, req.user.id);
    if (!server) throw new AppError('NOT_FOUND', 404, 'Server not found.');
    const limit = Math.min(Number(req.query.limit) || 20, 50);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const data = await auditRunRepo.listByServer(serverId, req.user.id, { limit, offset });
    res.json({ ok: true, data });
  } catch (err) {
    next(err);
  }
}

export async function getRun(req, res, next) {
  try {
    const run = await auditRunRepo.findOwned(req.params.runId, req.user.id);
    if (!run) throw new AppError('NOT_FOUND', 404, 'Audit run not found.');
    const findings = await auditFindingRepo.listByRun(run.id);
    res.json({
      ok: true,
      data: {
        ...run,
        coverage: coverageLine(run),
        findings,
      },
    });
  } catch (err) {
    next(err);
  }
}

export async function deleteRun(req, res, next) {
  try {
    const ok = await auditRunRepo.removeOwned(req.params.runId, req.user.id);
    if (!ok) throw new AppError('NOT_FOUND', 404, 'Audit run not found.');
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
}

export async function downloadPdf(req, res, next) {
  try {
    const run = await auditRunRepo.findOwned(req.params.runId, req.user.id);
    if (!run) throw new AppError('NOT_FOUND', 404, 'Audit run not found.');
    const server = await serverRepo.findOwned(run.serverId, req.user.id);
    if (!server) throw new AppError('NOT_FOUND', 404, 'Server not found.');
    const findings = await auditFindingRepo.listByRun(run.id);
    const buffer = await buildPdfBuffer(run, findings, server);
    const filename = pdfFilename(server, run);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(buffer);
  } catch (err) {
    next(err);
  }
}
