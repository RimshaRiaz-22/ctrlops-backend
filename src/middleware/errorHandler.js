import { logger } from '../utils/logger.js';

export class AppError extends Error {
  constructor(code, statusCode, message, hint) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
    this.hint = hint;
  }
}

export function errorHandler(err, _req, res, _next) {
  if (res.headersSent) {
    logger.error(err);
    return;
  }

  if (err instanceof AppError) {
    return res.status(err.statusCode).json({
      ok: false,
      error: {
        code: err.code,
        message: err.message,
        ...(err.hint ? { hint: err.hint } : {}),
      },
    });
  }

  logger.error(err);
  return res.status(500).json({
    ok: false,
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred.',
    },
  });
}
