import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseEnvironmentOutput,
  familyOf,
  buildAuditBatch,
} from '../../src/services/audits/environment.js';
import { sshHardeningChecks } from '../../src/services/audits/checks/ssh-hardening/index.js';

test('parseEnvironmentOutput: root', () => {
  const env = parseEnvironmentOutput(
    '===OS===\nID=ubuntu\nNAME="Ubuntu"\nVERSION_ID="22.04"\n===SUDO===\nEXIT:1\n===USER===\n0\n===DONE===\n',
  );
  assert.equal(env.sudoMode, 'ROOT');
  assert.equal(env.family, 'debian');
});

test('parseEnvironmentOutput: passwordless', () => {
  const env = parseEnvironmentOutput(
    '===OS===\nID=rocky\nNAME="Rocky"\n===SUDO===\nEXIT:0\n===USER===\n1000\n===DONE===\n',
  );
  assert.equal(env.sudoMode, 'PASSWORDLESS');
  assert.equal(env.family, 'rhel');
});

test('parseEnvironmentOutput: unavailable', () => {
  const env = parseEnvironmentOutput(
    '===OS===\nID=ubuntu\n===SUDO===\nsudo: a password is required\nEXIT:1\n===USER===\n1000\n===DONE===\n',
  );
  assert.equal(env.sudoMode, 'UNAVAILABLE');
});

test('familyOf alpine', () => {
  assert.equal(familyOf('alpine'), 'alpine');
});

test('buildAuditBatch includes timeout and markers', () => {
  const batch = buildAuditBatch(sshHardeningChecks.slice(0, 1), {
    sudoMode: 'PASSWORDLESS',
    family: 'debian',
  });
  assert.match(batch, /===CHECK:ssh-root-login===/);
  assert.match(batch, /timeout 10 sh -c/);
  assert.match(batch, /sudo -n /);
  assert.match(batch, /===DONE===/);
});
