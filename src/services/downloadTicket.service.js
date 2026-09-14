import { randomBytes } from 'crypto';

const TTL_MS = 60_000;
const tickets = new Map();

function purgeExpired() {
  const now = Date.now();
  for (const [id, rec] of tickets) {
    if (rec.expiresAt <= now) tickets.delete(id);
  }
}

export function issueTicket(payload) {
  purgeExpired();
  const ticket = randomBytes(24).toString('hex');
  tickets.set(ticket, {
    ...payload,
    expiresAt: Date.now() + TTL_MS,
  });
  return ticket;
}

export function consumeTicket(ticket) {
  if (!ticket) return null;
  purgeExpired();
  const rec = tickets.get(ticket);
  if (!rec) return null;
  tickets.delete(ticket);
  if (rec.expiresAt <= Date.now()) return null;
  return rec;
}

export function resetTicketsForTests() {
  tickets.clear();
}
