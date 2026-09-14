import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  add,
  remove,
  countFor,
  isAtCap,
  resetForTests,
  MAX_PER_USER_SERVER,
} from '../../src/services/terminalRegistry.js';

beforeEach(() => {
  resetForTests();
});

test('add and remove update the per user-server count', () => {
  add({ sessionId: 'a', userId: 'u1', serverId: 's1' });
  add({ sessionId: 'b', userId: 'u1', serverId: 's1' });
  add({ sessionId: 'c', userId: 'u1', serverId: 's2' });
  assert.equal(countFor('u1', 's1'), 2);
  assert.equal(countFor('u1', 's2'), 1);
  remove('a');
  assert.equal(countFor('u1', 's1'), 1);
});

test('cap is three sessions per user-server pair', () => {
  add({ sessionId: '1', userId: 'u1', serverId: 's1' });
  add({ sessionId: '2', userId: 'u1', serverId: 's1' });
  add({ sessionId: '3', userId: 'u1', serverId: 's1' });
  assert.equal(isAtCap('u1', 's1'), true);
  assert.equal(MAX_PER_USER_SERVER, 3);
  assert.equal(isAtCap('u1', 's2'), false);
  remove('2');
  assert.equal(isAtCap('u1', 's1'), false);
});
