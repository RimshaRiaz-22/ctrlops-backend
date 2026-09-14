import rateLimit from 'express-rate-limit';
import { env } from '../config/env.js';

const sshMessage = {
  ok: false,
  error: {
    code: 'RATE_LIMITED',
    message: 'Too many connection tests. Try again in a minute.',
    hint: 'Maximum 10 tests per minute per user.',
  },
};

export const sshActionLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `ssh:${req.user.id}`,
  validate: { xForwardedForHeader: false },
  message: sshMessage,
});

export const authLimiter = rateLimit({
  windowMs: 60_000,
  max: env.NODE_ENV === 'test' ? 1000 : 20,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false },
  message: {
    ok: false,
    error: {
      code: 'RATE_LIMITED',
      message: 'Too many authentication attempts. Try again in a minute.',
      hint: 'Maximum 20 login or register attempts per minute.',
    },
  },
});

export const terminalTicketLimiter = rateLimit({
  windowMs: 60_000,
  max: env.NODE_ENV === 'test' ? 1000 : 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `term:${req.user.id}`,
  validate: { xForwardedForHeader: false },
  message: {
    ok: false,
    error: {
      code: 'RATE_LIMITED',
      message: 'Too many terminal sessions. Try again in a minute.',
      hint: 'Maximum 30 terminal tickets per minute per user.',
    },
  },
});
