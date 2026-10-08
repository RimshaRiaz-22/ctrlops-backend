import { randomBytes } from 'crypto';

const TTL_MS = 30_000;
const tickets = new Map();

function purgeExpired() {
  const now = Date.now();
  for (const [id, rec] of tickets) {
    if (rec.expiresAt <= now) tickets.delete(id);
  }
}

export function issueTicket({ userId, serverId, purpose = 'terminal' }) {
  purgeExpired();
  const ticket = randomBytes(24).toString('hex');
  tickets.set(ticket, {
    userId,
    serverId,
    purpose,
    expiresAt: Date.now() + TTL_MS,
  });
  return { ticket, expiresIn: 30 };
}

/** Delete immediately, then validate — a failed check must not leave a reusable ticket. */
export function consumeTicket(ticket, expectedPurpose) {
  if (!ticket) return null;
  purgeExpired();
  const rec = tickets.get(ticket);
  tickets.delete(ticket);
  if (!rec) return null;
  if (rec.expiresAt <= Date.now()) return null;
  if (expectedPurpose && rec.purpose && rec.purpose !== expectedPurpose) return null;
  return { userId: rec.userId, serverId: rec.serverId };
}

export function peekTicketForTests(ticket) {
  return tickets.get(ticket) ?? null;
}

export function expireTicketForTests(ticket) {
  const rec = tickets.get(ticket);
  if (rec) rec.expiresAt = Date.now() - 1;
}

export function resetTicketsForTests() {
  tickets.clear();
}

export const TERMINAL_TICKET_TTL_MS = TTL_MS;
