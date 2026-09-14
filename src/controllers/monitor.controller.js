import { AppError } from '../middleware/errorHandler.js';
import * as serverRepo from '../repositories/server.repository.js';
import { issueTicket } from '../services/terminalTicket.service.js';

export async function createTicket(req, res, next) {
  try {
    const server = await serverRepo.findOwned(req.body.serverId, req.user.id);
    if (!server) {
      throw new AppError('NOT_FOUND', 404, 'Server not found.');
    }
    const data = issueTicket({
      userId: req.user.id,
      serverId: server.id,
      purpose: 'monitor',
    });
    res.json({ ok: true, data });
  } catch (err) {
    next(err);
  }
}
