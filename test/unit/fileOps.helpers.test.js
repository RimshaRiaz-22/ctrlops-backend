import { test } from 'node:test';
import assert from 'node:assert/strict';
import { entryType, formatMode } from '../../src/utils/posixMode.js';
import { mapSftpError } from '../../src/services/fileError.service.js';
import { languageFromPath, isBinaryBuffer } from '../../src/utils/languageFromPath.js';

test('entryType directory file symlink', () => {
  assert.equal(entryType(0o040755), 'directory');
  assert.equal(entryType(0o100644), 'file');
  assert.equal(entryType(0o120777), 'symlink');
});

test('formatMode 0755 0644 0600', () => {
  assert.equal(formatMode(0o100755), '-rwxr-xr-x');
  assert.equal(formatMode(0o100644), '-rw-r--r--');
  assert.equal(formatMode(0o100600), '-rw-------');
  assert.equal(formatMode(0o040755), 'drwxr-xr-x');
});

test('fileError maps SFTP codes', () => {
  assert.equal(mapSftpError({ code: 2 }).statusCode, 404);
  assert.equal(mapSftpError({ code: 3 }).statusCode, 403);
  assert.equal(mapSftpError({ code: 'ENOTDIR' }).statusCode, 400);
  assert.equal(mapSftpError({ code: 7 }).statusCode, 502);
  assert.equal(mapSftpError({ code: 2 }).message.includes('no longer exists'), true);
  assert.equal(mapSftpError({ code: 3 }).message.includes('Permission denied'), true);
});

test('languageFromPath', () => {
  assert.equal(languageFromPath('/etc/nginx/nginx.conf'), 'nginx');
  assert.equal(languageFromPath('/home/ubuntu/.env'), 'dotenv');
  assert.equal(languageFromPath('/app/docker-compose.yml'), 'yaml');
  assert.equal(languageFromPath('/tmp/unknown.bin'), 'plaintext');
});

test('isBinaryBuffer', () => {
  assert.equal(isBinaryBuffer(Buffer.from([0x00, 0x61])), true);
  assert.equal(isBinaryBuffer(Buffer.from('hello')), false);
  assert.equal(isBinaryBuffer(Buffer.alloc(0)), false);
});
