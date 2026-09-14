import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { sshActionLimiter } from '../middleware/rateLimit.js';
import {
  testConnectionSchema,
  createServerSchema,
  updateServerSchema,
} from '../schemas/server.schema.js';
import * as serverController from '../controllers/server.controller.js';
import fileRoutes from './file.routes.js';

const router = Router();

router.use(requireAuth);

router.get('/', serverController.list);
router.post(
  '/test-connection',
  sshActionLimiter,
  validate(testConnectionSchema),
  serverController.testConnection,
);
router.post(
  '/',
  sshActionLimiter,
  validate(createServerSchema),
  serverController.create,
);
router.patch('/:id', validate(updateServerSchema), serverController.update);
router.get('/:id', serverController.getOne);
router.delete('/:id', serverController.remove);
router.post('/:id/ping', sshActionLimiter, serverController.ping);
router.use('/:id/files', fileRoutes);

export default router;
