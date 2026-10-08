import { z } from 'zod';

export const mkdirSchema = z.object({
  path: z.string().min(1),
  name: z.string().min(1).max(255).refine((v) => !v.includes('/') && !v.includes('\0'), {
    message: 'Folder name cannot contain / or null bytes.',
  }),
});

export const renameSchema = z.object({
  path: z.string().min(1),
  newName: z.string().min(1).max(255).refine((v) => !v.includes('/') && !v.includes('\0'), {
    message: 'Name cannot contain / or null bytes.',
  }),
});

export const deleteSchema = z.object({
  paths: z.array(z.string().min(1)).min(1),
  recursive: z.boolean().optional().default(false),
});

export const unzipSchema = z.object({
  path: z.string().min(1),
});

export const downloadTicketSchema = z.object({
  path: z.string().min(1),
});

export const zipSchema = z.object({
  directory: z.string().min(1),
  files: z.array(z.string().min(1)).min(1),
});

export const contentPutSchema = z.object({
  path: z.string().min(1),
  content: z.string(),
  expectedModifiedAt: z.string().optional(),
  force: z.boolean().optional().default(false),
});
