import { z } from 'zod';

export const runAuditsSchema = z.object({
  auditIds: z.array(z.string().min(1).max(64)).min(1).max(25),
});
