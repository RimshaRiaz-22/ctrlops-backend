import { test } from 'node:test';
import assert from 'node:assert/strict';
import { implementedAuditIds, getChecksForAudit } from '../../src/services/audits/checks/index.js';
import { dockerDaemonSocketChecks } from '../../src/services/audits/checks/docker/index.js';
import { webTlsChecks } from '../../src/services/audits/checks/web/index.js';
import { dbNetworkExposureChecks } from '../../src/services/audits/checks/database/index.js';
import { AUDIT_CATALOG } from '../../src/services/audits/catalog.js';

test('all 25 catalog audits are implemented', () => {
  const ids = implementedAuditIds();
  assert.equal(ids.size, 25);
  for (const a of AUDIT_CATALOG) {
    assert.ok(ids.has(a.id), `missing ${a.id}`);
    assert.equal(
      getChecksForAudit(a.id).length,
      a.checkCount,
      `${a.id} checkCount mismatch`,
    );
  }
});

test('docker socket CRITICAL on 2375', () => {
  const c = dockerDaemonSocketChecks.find((x) => x.id === 'docker-socket-tcp');
  assert.equal(c.severity, 'CRITICAL');
  assert.equal(c.evaluate('NONE').status, 'PASS');
  assert.equal(c.evaluate('LISTEN 0 128 0.0.0.0:2375 0.0.0.0:*').status, 'FAIL');
  assert.equal(c.evaluate('LISTEN 0 128 0.0.0.0:2376 0.0.0.0:*').status, 'WARNING');
});

test('web TLS :443 missing is FAIL', () => {
  const c = webTlsChecks.find((x) => x.id === 'web-tls-listen');
  assert.equal(c.evaluate('NONE').status, 'FAIL');
  assert.equal(c.evaluate('LISTEN 0 128 *:443 *:*').status, 'PASS');
});

test('db public bind is FAIL', () => {
  const c = dbNetworkExposureChecks.find((x) => x.id === 'db-bind-public');
  assert.equal(c.evaluate('NONE').status, 'PASS');
  assert.equal(c.evaluate('LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*').status, 'FAIL');
});
