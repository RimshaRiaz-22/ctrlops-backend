import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { sshActionLimiter } from '../middleware/rateLimit.js';
import { runAuditsSchema } from '../schemas/audit.schema.js';
import * as auditController from '../controllers/audit.controller.js';

const router = Router({ mergeParams: true });

router.use(requireAuth);

router.get('/catalog', auditController.catalog);
router.get('/runs/:runId', auditController.getRun);
router.delete('/runs/:runId', auditController.deleteRun);
router.get('/runs/:runId/pdf', auditController.downloadPdf);

export default router;

/** Nested under /api/servers/:serverId/audits */
export function createServerAuditRouter() {
  const r = Router({ mergeParams: true });
  r.use(requireAuth);
  r.get('/sudo-status', sshActionLimiter, auditController.sudoStatus);
  r.post('/run', sshActionLimiter, validate(runAuditsSchema), auditController.startRun);
  r.get('/runs', auditController.listRuns);
  return r;
}
