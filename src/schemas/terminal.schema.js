import { z } from 'zod';

export const terminalTicketSchema = z.object({
  serverId: z.string().uuid(),
});
