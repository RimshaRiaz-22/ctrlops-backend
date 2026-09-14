import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { testConnection } from '../../src/services/ssh.service.js';

const live = process.env.LIVE_SSH === '1';
const keyPath = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../keys/test',
);

test(
  'live SSH against local sshd :2222',
  { skip: live && fs.existsSync(keyPath) ? false : 'set LIVE_SSH=1 with keys/test and sshd on :2222' },
  async () => {
    const privateKey = fs.readFileSync(keyPath, 'utf8');
    const result = await testConnection({
      host: '127.0.0.1',
      port: 2222,
      username: process.env.USER || 'testuser',
      privateKey,
    });
    assert.equal(result.ok, true);
    assert.ok(result.data.hostKeyFingerprint);
  },
);
