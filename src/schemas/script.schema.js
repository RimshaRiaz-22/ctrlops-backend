import { z } from 'zod';

const color = z.string().max(16).nullable().optional();
const tags = z.array(z.string().min(1).max(32)).max(20).optional();

export const createScriptSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(2000).nullable().optional(),
  body: z.string().min(1).max(20_000),
  tags: tags.default([]),
  color,
});

export const updateScriptSchema = z
  .object({
    name: z.string().min(1).max(100).optional(),
    description: z.string().max(2000).nullable().optional(),
    body: z.string().min(1).max(20_000).optional(),
    tags,
    color,
  })
  .refine(
    (data) =>
      data.name !== undefined ||
      data.description !== undefined ||
      data.body !== undefined ||
      data.tags !== undefined ||
      data.color !== undefined,
    { message: 'At least one field is required' },
  );
