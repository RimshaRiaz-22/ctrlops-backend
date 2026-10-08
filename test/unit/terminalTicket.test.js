import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  issueTicket,
  consumeTicket,
  expireTicketForTests,
  resetTicketsForTests,
} from '../../src/services/terminalTicket.service.js';

test('valid ticket passes once', () => {
  resetTicketsForTests();
  const { ticket, expiresIn } = issueTicket({ userId: 'u1', serverId: 's1' });
  assert.equal(expiresIn, 30);
  assert.equal(typeof ticket, 'string');
  assert.ok(ticket.length >= 32);
  const rec = consumeTicket(ticket);
  assert.deepEqual(rec, { userId: 'u1', serverId: 's1' });
});

test('reused ticket is rejected', () => {
  resetTicketsForTests();
  const { ticket } = issueTicket({ userId: 'u1', serverId: 's1' });
  assert.ok(consumeTicket(ticket));
  assert.equal(consumeTicket(ticket), null);
});

test('expired ticket is rejected', () => {
  resetTicketsForTests();
  const { ticket } = issueTicket({ userId: 'u1', serverId: 's1' });
  expireTicketForTests(ticket);
  assert.equal(consumeTicket(ticket), null);
});

test('unknown ticket is rejected', () => {
  resetTicketsForTests();
  assert.equal(consumeTicket('not-a-real-ticket'), null);
  assert.equal(consumeTicket(''), null);
  assert.equal(consumeTicket(null), null);
});

test('failed consume deletes the ticket so it cannot be retried', () => {
  resetTicketsForTests();
  const { ticket } = issueTicket({ userId: 'u1', serverId: 's1' });
  expireTicketForTests(ticket);
  assert.equal(consumeTicket(ticket), null);
  assert.equal(consumeTicket(ticket), null);
});
