import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  blockPrivateIp,
  assertSshTargetsAllowed,
} from '../../src/utils/ipGuard.js';

const blocked = [
  '127.0.0.1',
  'localhost',
  '169.254.169.254',
  '10.0.0.1',
  '192.168.1.1',
  '172.16.0.1',
  'metadata.google.internal',
  'foo.local',
];

for (const host of blocked) {
  test(`blocks ${host} when private IPs are disallowed`, () => {
    const result = blockPrivateIp(host, { allowPrivateIps: false });
    assert.equal(result?.code, 'HOST_BLOCKED');
  });
}

test('allows a public IPv4 when private IPs are disallowed', () => {
  assert.equal(blockPrivateIp('8.8.8.8', { allowPrivateIps: false }), null);
});

test('allows private IPs when the allow flag is set', () => {
  assert.equal(blockPrivateIp('127.0.0.1', { allowPrivateIps: true }), null);
  assert.equal(blockPrivateIp('169.254.169.254', { allowPrivateIps: true }), null);
});

test('blocks a hostname that resolves to the metadata IP', async () => {
  const lookup = async () => [{ address: '169.254.169.254', family: 4 }];
  const result = await assertSshTargetsAllowed('evil.example.com', {
    allowPrivateIps: false,
    lookup,
  });
  assert.equal(result?.code, 'HOST_BLOCKED');
});

test('blocks a private bastion host in ProxyCommand', async () => {
  const result = await assertSshTargetsAllowed('8.8.8.8', {
    allowPrivateIps: false,
    proxyCommand: 'ssh -W %h:%p jump@10.0.0.5',
  });
  assert.equal(result?.code, 'HOST_BLOCKED');
});

test('allows public target and public bastion', async () => {
  const lookup = async () => [{ address: '1.1.1.1', family: 4 }];
  const result = await assertSshTargetsAllowed('example.com', {
    allowPrivateIps: false,
    proxyCommand: 'ssh -W %h:%p jump@bastion.example.net',
    lookup,
  });
  assert.equal(result, null);
});
