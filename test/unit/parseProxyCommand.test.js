import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseProxyCommand } from '../../src/utils/parseProxyCommand.js';

test('parses ssh -W %h:%p user@host', () => {
  assert.deepEqual(parseProxyCommand('ssh -W %h:%p ubuntu@bastion.example.com'), {
    username: 'ubuntu',
    host: 'bastion.example.com',
    port: 22,
  });
});

test('parses custom bastion port', () => {
  assert.deepEqual(parseProxyCommand('ssh -W %h:%p jump@10.1.2.3 -p 2222'), {
    username: 'jump',
    host: '10.1.2.3',
    port: 2222,
  });
});

test('returns null for empty or unsupported strings', () => {
  assert.equal(parseProxyCommand(''), null);
  assert.equal(parseProxyCommand(null), null);
  assert.equal(parseProxyCommand('nc -X connect -x proxy:8080 %h %p'), null);
  assert.equal(parseProxyCommand('ssh user@host'), null);
});
