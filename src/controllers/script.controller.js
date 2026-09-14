import { AppError } from '../middleware/errorHandler.js';
import * as scriptRepo from '../repositories/script.repository.js';

export async function list(req, res, next) {
  try {
    const data = await scriptRepo.listByUser(req.user.id);
    res.json({ ok: true, data });
  } catch (err) {
    next(err);
  }
}

export async function create(req, res, next) {
  try {
    const data = await scriptRepo.create(req.user.id, req.body);
    res.status(201).json({ ok: true, data });
  } catch (err) {
    next(err);
  }
}

export async function update(req, res, next) {
  try {
    const data = await scriptRepo.update(req.user.id, req.params.id, req.body);
    if (!data) throw new AppError('NOT_FOUND', 404, 'Script not found.');
    res.json({ ok: true, data });
  } catch (err) {
    next(err);
  }
}

export async function remove(req, res, next) {
  try {
    const ok = await scriptRepo.remove(req.user.id, req.params.id);
    if (!ok) throw new AppError('NOT_FOUND', 404, 'Script not found.');
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
}

export async function recordRun(req, res, next) {
  try {
    const data = await scriptRepo.recordRun(req.user.id, req.params.id);
    if (!data) throw new AppError('NOT_FOUND', 404, 'Script not found.');
    res.json({ ok: true, data });
  } catch (err) {
    next(err);
  }
}
