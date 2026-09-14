import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  commandDictionary,
  matchSuggestions,
} from '../../../frontend/src/features/terminal/data/commandDictionary.js';
import {
  extractVariables,
  substituteVariables,
} from '../../../frontend/src/features/terminal/utils/variables.js';

test('prefix match on commands', () => {
  const hits = matchSuggestions('sys', commandDictionary);
  assert.ok(hits.some((h) => h.label === 'systemctl'));
});

test('subcommand match for pm2 l', () => {
  const hits = matchSuggestions('pm2 l', commandDictionary);
  const labels = hits.map((h) => h.label);
  assert.ok(labels.includes('list'));
  assert.ok(labels.includes('logs'));
  assert.ok(labels.includes('logrotate'));
  assert.ok(labels.includes('login'));
  assert.ok(labels.includes('link'));
});

test('no match and empty input', () => {
  assert.deepEqual(matchSuggestions('', commandDictionary), []);
  assert.deepEqual(matchSuggestions('zzzznope', commandDictionary), []);
});

test('file paths suppress suggestions', () => {
  assert.deepEqual(matchSuggestions('cat /etc/pass', commandDictionary), []);
});

test('variable substitution: single, multiple, missing, special chars', () => {
  assert.deepEqual(extractVariables('ls {{path}}'), ['path']);
  assert.equal(substituteVariables('ls {{path}}', { path: '/var/www' }), 'ls /var/www');
  assert.equal(
    substituteVariables('echo {{a}} {{b}}', { a: '1', b: '2' }),
    'echo 1 2',
  );
  assert.throws(() => substituteVariables('ls {{path}}', {}));
  assert.equal(
    substituteVariables('echo {{msg}}', { msg: 'hello; rm -rf /' }),
    'echo hello; rm -rf /',
  );
});
