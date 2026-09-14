import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import * as preferenceController from '../controllers/preference.controller.js';

const patchSchema = z.object({
  fileManagerLayout: z.enum(['list', 'grid', 'compact', 'columns', 'gallery']).optional(),
  showHiddenFiles: z.boolean().optional(),
  editorTheme: z.enum(['dark', 'light']).optional(),
});

const router = Router();
router.use(requireAuth);
router.get('/', preferenceController.getPreferences);
router.patch('/', validate(patchSchema), preferenceController.patchPreferences);

export default router;
