import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applicationSecurityChecks } from '../../src/services/audits/checks/application-security/index.js';
import { fileSystemChecks } from '../../src/services/audits/checks/file-system/index.js';
import { firewallNetworkChecks } from '../../src/services/audits/checks/firewall-network/index.js';
import { userAccountChecks } from '../../src/services/audits/checks/user-account/index.js';
import { kernelSysctlChecks } from '../../src/services/audits/checks/kernel-sysctl/index.js';
import { updatesPatchingChecks } from '../../src/services/audits/checks/updates-patching/index.js';
import { implementedAuditIds, getChecksForAudit } from '../../src/services/audits/checks/index.js';

function byId(checks, id) {
  return checks.find((c) => c.id === id);
}

test('all 7 Server audits are registered with expected check counts', () => {
  const ids = implementedAuditIds();
  assert.ok(ids.size >= 7);
  assert.equal(getChecksForAudit('application-security').length, 5);
  assert.equal(getChecksForAudit('file-system').length, 7);
  assert.equal(getChecksForAudit('firewall-network').length, 6);
  assert.equal(getChecksForAudit('user-account').length, 6);
  assert.equal(getChecksForAudit('kernel-sysctl').length, 5);
  assert.equal(getChecksForAudit('updates-patching').length, 4);
  assert.equal(getChecksForAudit('ssh-hardening').length, 7);
});

test('application-security: node version + public DB bind', () => {
  const node = byId(applicationSecurityChecks, 'app-node-version');
  assert.equal(node.evaluate('v16.0.0').status, 'FAIL');
  assert.equal(node.evaluate('v20.11.0').status, 'PASS');
  const db = byId(applicationSecurityChecks, 'app-db-listening-localhost');
  assert.equal(db.evaluate('NONE').status, 'PASS');
  assert.equal(
    db.evaluate('LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*').status,
    'FAIL',
  );
});

test('file-system: shadow + world-writable', () => {
  const shadow = byId(fileSystemChecks, 'fs-shadow-perms');
  assert.equal(shadow.evaluate('640 root:shadow').status, 'PASS');
  assert.equal(shadow.evaluate('644 root:root').status, 'FAIL');
  const ww = byId(fileSystemChecks, 'fs-world-writable-files');
  assert.equal(ww.evaluate('0').status, 'PASS');
  assert.equal(ww.evaluate('12').status, 'FAIL');
});

test('firewall-network: family-specific + syncookies', () => {
  const fw = byId(firewallNetworkChecks, 'fw-enabled');
  assert.equal(fw.evaluate('Status: active', '', 0, { family: 'debian' }).status, 'PASS');
  assert.equal(fw.evaluate('running', '', 0, { family: 'rhel' }).status, 'PASS');
  assert.equal(fw.evaluate('inactive', '', 0, { family: 'debian' }).status, 'FAIL');
  const syn = byId(firewallNetworkChecks, 'fw-syn-cookies');
  assert.equal(syn.evaluate('1').status, 'PASS');
  assert.equal(syn.evaluate('0').status, 'FAIL');
});

test('user-account: uid0 and empty hashes', () => {
  const uid0 = byId(userAccountChecks, 'user-uid0-accounts');
  assert.equal(uid0.evaluate('root').status, 'PASS');
  assert.equal(uid0.evaluate('root\ntoor').status, 'FAIL');
  const empty = byId(userAccountChecks, 'user-empty-password-hashes');
  assert.equal(empty.evaluate('').status, 'PASS');
  assert.equal(empty.evaluate('guest').status, 'FAIL');
});

test('kernel-sysctl: ASLR and source route', () => {
  const aslr = byId(kernelSysctlChecks, 'sysctl-aslr');
  assert.equal(aslr.evaluate('2').status, 'PASS');
  assert.equal(aslr.evaluate('0').status, 'FAIL');
  const src = byId(kernelSysctlChecks, 'sysctl-accept-source-route');
  assert.equal(src.evaluate('0\n0').status, 'PASS');
  assert.equal(src.evaluate('1\n0').status, 'FAIL');
});

test('updates-patching: reboot + unattended', () => {
  const reboot = byId(updatesPatchingChecks, 'upd-reboot-required');
  assert.equal(reboot.evaluate('NO').status, 'PASS');
  assert.equal(reboot.evaluate('YES\nlinux-image').status, 'WARNING');
  const auto = byId(updatesPatchingChecks, 'upd-unattended-upgrades');
  assert.equal(
    auto.evaluate('APT::Periodic::Unattended-Upgrade "1";', '', 0, { family: 'debian' })
      .status,
    'PASS',
  );
  assert.equal(auto.evaluate('MISSING', '', 0, { family: 'rhel' }).status, 'SKIP');
});
