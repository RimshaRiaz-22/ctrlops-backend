import { test } from 'node:test';
import assert from 'node:assert/strict';
import { attachmentDisposition } from '../../src/utils/contentDisposition.js';

test('spaces and unicode stay in the download filename', () => {
  const header = attachmentDisposition('Q3 report 报表.txt');
  assert.match(header, /^attachment;/);
  assert.match(header, /filename="Q3%20report%20%E6%8A%A5%E8%A1%A8\.txt"/);
  assert.match(header, /filename\*=UTF-8''Q3%20report%20%E6%8A%A5%E8%A1%A8\.txt/);
});
