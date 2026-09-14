import { z } from 'zod';
import * as authService from '../services/auth.service.js';

const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

export async function register(req, res, next) {
  try {
    const body = credentialsSchema.parse(req.body);
    const result = await authService.register(body);
    res.status(201).json({ ok: true, ...result });
  } catch (err) {
    if (err.name === 'ZodError') {
      return res.status(400).json({
        ok: false,
        error: { code: 'VALIDATION_ERROR', message: err.issues[0]?.message },
      });
    }
    next(err);
  }
}

export async function login(req, res, next) {
  try {
    const body = credentialsSchema.parse(req.body);
    const result = await authService.login(body);
    res.json({ ok: true, ...result });
  } catch (err) {
    if (err.name === 'ZodError') {
      return res.status(400).json({
        ok: false,
        error: { code: 'VALIDATION_ERROR', message: err.issues[0]?.message },
      });
    }
    next(err);
  }
}

export async function refresh(req, res, next) {
  try {
    const result = await authService.refresh(req.body.refreshToken);
    res.json({
      ok: true,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  } catch (err) {
    next(err);
  }
}
