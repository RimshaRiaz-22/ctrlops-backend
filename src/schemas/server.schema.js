import { z } from 'zod';

/** Uppercase enums matching Postgres + frontend Zod (not lowercase doc examples). */
export const serverTypeEnum = z.enum([
  'PRODUCTION',
  'STAGING',
  'DEVELOPMENT',
  'DATABASE',
  'WEB',
  'DOCKER',
  'OTHER',
]);

export const authMethodEnum = z.enum(['KEY', 'PEM', 'PASSWORD']);

const MAX_KEY_SIZE = 16 * 1024;

function refineAuth(data, ctx) {
  if (data.authMethod === 'PASSWORD') {
    if (!data.password) {
      ctx.addIssue({
        code: 'custom',
        message: 'Password is required for PASSWORD auth',
        path: ['password'],
      });
    }
    return;
  }

  if (!data.privateKey) {
    ctx.addIssue({
      code: 'custom',
      message: 'Private key is required',
      path: ['privateKey'],
    });
    return;
  }

  if (data.privateKey.length > MAX_KEY_SIZE) {
    ctx.addIssue({
      code: 'custom',
      message: 'Key exceeds 16 KB limit',
      path: ['privateKey'],
    });
  }

  const trimmed = data.privateKey.trim();
  if (
    trimmed.startsWith('ssh-rsa') ||
    trimmed.startsWith('ssh-ed25519') ||
    trimmed.startsWith('ecdsa-sha2-')
  ) {
    ctx.addIssue({
      code: 'custom',
      message: 'This is a public key. Use the private key (without .pub).',
      path: ['privateKey'],
    });
  }
}

const connectionFields = {
  host: z.string().min(1, 'Host is required').max(255),
  port: z.coerce.number().int().min(1).max(65535).default(22),
  username: z.string().min(1, 'Username is required').max(64),
  authMethod: authMethodEnum,
  privateKey: z.string().optional(),
  passphrase: z.string().optional(),
  password: z.string().optional().nullable(),
  proxyCommand: z.string().optional().nullable(),
};

export const testConnectionSchema = z.object(connectionFields).superRefine(refineAuth);

export const createServerSchema = z
  .object({
    ...connectionFields,
    name: z.string().min(1, 'Name is required').max(50),
    type: serverTypeEnum.default('OTHER'),
  })
  .superRefine(refineAuth);

export const updateServerSchema = z
  .object({
    name: z.string().min(1, 'Name is required').max(50).optional(),
    type: serverTypeEnum.optional(),
    isFavorite: z.boolean().optional(),
  })
  .refine(
    (data) =>
      data.name !== undefined ||
      data.type !== undefined ||
      data.isFavorite !== undefined,
    { message: 'At least one field is required' },
  );
