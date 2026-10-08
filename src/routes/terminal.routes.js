import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { terminalTicketLimiter } from '../middleware/rateLimit.js';
import { terminalTicketSchema } from '../schemas/terminal.schema.js';
import * as terminalController from '../controllers/terminal.controller.js';

const router = Router();
router.use(requireAuth);
router.post(
  '/ticket',
  terminalTicketLimiter,
  validate(terminalTicketSchema),
  terminalController.createTicket,
);

export default router;
