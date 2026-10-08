import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { createScriptSchema, updateScriptSchema } from '../schemas/script.schema.js';
import * as scriptController from '../controllers/script.controller.js';

const router = Router();
router.use(requireAuth);
router.get('/', scriptController.list);
router.post('/', validate(createScriptSchema), scriptController.create);
router.patch('/:id', validate(updateScriptSchema), scriptController.update);
router.delete('/:id', scriptController.remove);
router.post('/:id/run', scriptController.recordRun);

export default router;
