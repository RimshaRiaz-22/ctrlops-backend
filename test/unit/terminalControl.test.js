import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseControlMessage } from '../../src/services/terminalControl.js';

test('valid resize is accepted', () => {
  assert.deepEqual(parseControlMessage('{"type":"resize","cols":120,"rows":40}'), {
    ok: true,
    type: 'resize',
    cols: 120,
    rows: 40,
  });
});

test('malformed JSON is rejected', () => {
  assert.equal(parseControlMessage('{not json').ok, false);
});

test('missing fields are rejected', () => {
  assert.equal(parseControlMessage('{"type":"resize"}').ok, false);
  assert.equal(parseControlMessage('{"type":"resize","cols":80}').ok, false);
});

test('out-of-range cols/rows are rejected', () => {
  assert.equal(parseControlMessage('{"type":"resize","cols":0,"rows":24}').ok, false);
  assert.equal(parseControlMessage('{"type":"resize","cols":80,"rows":1001}').ok, false);
  assert.equal(parseControlMessage('{"type":"resize","cols":-1,"rows":24}').ok, false);
});

test('string cols are rejected (injection / coercion attempt)', () => {
  assert.equal(
    parseControlMessage('{"type":"resize","cols":"80; DROP TABLE","rows":24}').ok,
    false,
  );
});

test('ping is accepted', () => {
  assert.deepEqual(parseControlMessage('{"type":"ping"}'), { ok: true, type: 'ping' });
});

test('unknown types are rejected', () => {
  assert.equal(parseControlMessage('{"type":"exec","cmd":"rm -rf /"}').ok, false);
});
