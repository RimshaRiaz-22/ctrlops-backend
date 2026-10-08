import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sshHardeningChecks } from '../../src/services/audits/checks/ssh-hardening/index.js';

function check(id) {
  return sshHardeningChecks.find((c) => c.id === id);
}

test('ssh-root-login PASS/FAIL/WARNING', () => {
  const c = check('ssh-root-login');
  assert.equal(c.evaluate('PermitRootLogin no').status, 'PASS');
  assert.equal(c.evaluate('PermitRootLogin yes').status, 'FAIL');
  assert.equal(c.evaluate('').status, 'WARNING');
});

test('ssh-password-auth unset is WARNING not PASS', () => {
  const c = check('ssh-password-auth');
  assert.equal(c.evaluate('').status, 'WARNING');
  assert.equal(c.evaluate('PasswordAuthentication no').status, 'PASS');
  assert.equal(c.evaluate('PasswordAuthentication yes').status, 'FAIL');
});

test('ssh-max-auth-tries', () => {
  const c = check('ssh-max-auth-tries');
  assert.equal(c.evaluate('MaxAuthTries 3').status, 'PASS');
  assert.equal(c.evaluate('MaxAuthTries 6').status, 'FAIL');
});

test('ssh-permit-empty-passwords', () => {
  const c = check('ssh-permit-empty-passwords');
  assert.equal(c.evaluate('PermitEmptyPasswords no').status, 'PASS');
  assert.equal(c.evaluate('PermitEmptyPasswords yes').status, 'FAIL');
});
