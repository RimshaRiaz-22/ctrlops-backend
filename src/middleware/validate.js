import { AppError } from './errorHandler.js';

export function validate(schema) {
  return (req, _res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      const first = result.error.issues[0];
      return next(
        new AppError(
          'VALIDATION_ERROR',
          400,
          first?.message ?? 'Invalid request body',
        ),
      );
    }
    req.body = result.data;
    return next();
  };
}
