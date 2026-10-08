import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  issueTicket,
  consumeTicket,
  resetTicketsForTests,
} from '../../src/services/terminalTicket.service.js';

test('monitor ticket cannot open a terminal socket', () => {
  resetTicketsForTests();
  const { ticket } = issueTicket({ userId: 'u1', serverId: 's1', purpose: 'monitor' });
  assert.equal(consumeTicket(ticket, 'terminal'), null);
});

test('terminal ticket cannot open a monitor socket', () => {
  resetTicketsForTests();
  const { ticket } = issueTicket({ userId: 'u1', serverId: 's1', purpose: 'terminal' });
  assert.equal(consumeTicket(ticket, 'monitor'), null);
});
