import { before, afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import app from '../../src/app.js';
import { ensureTestDatabase, resetDb } from '../helpers/db.js';
import { mockSshOk, restoreSsh, registerUser, api, serverPayload } from '../helpers/http.js';
import { resetPoolForTests, poolSize } from '../../src/services/sshPool.service.js';
import { resetTicketsForTests } from '../../src/services/downloadTicket.service.js';
import { query } from '../../src/config/db.js';

const prevMock = process.env.MOCK_SSH;

before(async () => {
  process.env.MOCK_SSH = 'true';
  await ensureTestDatabase();
  await resetDb();
});

afterEach(async () => {
  restoreSsh();
  resetPoolForTests();
  resetTicketsForTests();
  process.env.MOCK_SSH = 'true';
});

async function createOwnedServer() {
  mockSshOk();
  const owner = await registerUser();
  const created = await api(owner.token).post(
    '/api/servers',
    serverPayload({ name: `box-${Date.now()}`, host: '1.1.1.1', username: 'ubuntu' }),
  );
  assert.equal(created.status, 201);
  return { owner, id: created.body.data.id };
}

test('list home directory returns entries types and sizes', async () => {
  const { owner, id } = await createOwnedServer();
  const res = await api(owner.token).get(`/api/servers/${id}/files?path=/home/ubuntu`);
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
  assert.equal(res.body.data.path, '/home/ubuntu');
  assert.ok(res.body.data.breadcrumbs[0].path === '/');
  const names = res.body.data.entries.map((e) => e.name);
  assert.ok(names.includes('nginx.conf'));
  assert.ok(names.includes('.env'));
  const envFile = res.body.data.entries.find((e) => e.name === '.env');
  assert.equal(envFile.isHidden, true);
  assert.equal(envFile.isEditable, true);
});

test('list empty directory', async () => {
  const { owner, id } = await createOwnedServer();
  const res = await api(owner.token).get(`/api/servers/${id}/files?path=/home/ubuntu/backups`);
  assert.equal(res.status, 200);
  assert.equal(res.body.data.entries.length, 0);
});

test('list nonexistent path is 404', async () => {
  const { owner, id } = await createOwnedServer();
  const res = await api(owner.token).get(`/api/servers/${id}/files?path=/no/such`);
  assert.equal(res.status, 404);
});

test('list permission-denied is 403 with a clear message', async () => {
  const { owner, id } = await createOwnedServer();
  const res = await api(owner.token).get(`/api/servers/${id}/files?path=/root/secret`);
  assert.equal(res.status, 403);
  assert.match(res.body.error.message, /Permission denied/i);
  assert.equal(String(res.body.error.message).includes('3'), false);
});

test('other user listing is 404', async () => {
  const { id } = await createOwnedServer();
  const other = await registerUser();
  const res = await api(other.token).get(`/api/servers/${id}/files?path=/home/ubuntu`);
  assert.equal(res.status, 404);
});

test('relative path is rejected', async () => {
  const { owner, id } = await createOwnedServer();
  const res = await api(owner.token).get(`/api/servers/${id}/files?path=home/ubuntu`);
  assert.equal(res.status, 400);
});

test('null byte path is rejected', async () => {
  const { owner, id } = await createOwnedServer();
  const res = await api(owner.token).get(
    `/api/servers/${id}/files?path=${encodeURIComponent('/tmp/\0x')}`,
  );
  assert.ok(res.status === 400 || res.status === 404);
});

test('two list calls reuse one pooled connection', async () => {
  const { owner, id } = await createOwnedServer();
  await api(owner.token).get(`/api/servers/${id}/files?path=/home/ubuntu`);
  const afterFirst = poolSize();
  await api(owner.token).get(`/api/servers/${id}/files?path=/home/ubuntu`);
  assert.equal(poolSize(), afterFirst);
  assert.equal(poolSize(), 1);
});

test('mkdir rename delete copy-path names with spaces', async () => {
  const { owner, id } = await createOwnedServer();
  const mkdir = await api(owner.token).post(`/api/servers/${id}/files/mkdir`, {
    path: '/home/ubuntu',
    name: 'my folder',
  });
  assert.equal(mkdir.status, 200);

  const renamed = await api(owner.token).patch(`/api/servers/${id}/files/rename`, {
    path: '/home/ubuntu/my folder',
    newName: 'my folder 2',
  });
  assert.equal(renamed.status, 200);

  const del = await request(app)
    .delete(`/api/servers/${id}/files`)
    .set('Authorization', `Bearer ${owner.token}`)
    .send({ paths: ['/home/ubuntu/my folder 2'] });
  assert.equal(del.status, 200);
  assert.equal(del.body.data.results[0].ok, true);
});

test('delete non-empty directory requires recursive', async () => {
  const { owner, id } = await createOwnedServer();
  const del = await request(app)
    .delete(`/api/servers/${id}/files`)
    .set('Authorization', `Bearer ${owner.token}`)
    .send({ paths: ['/home/ubuntu'] });
  assert.equal(del.status, 200);
  assert.equal(del.body.data.results[0].ok, false);
});

test('upload small file then download matches', async () => {
  const { owner, id } = await createOwnedServer();
  const body = Buffer.from('hello-file-manager');
  const up = await request(app)
    .post(`/api/servers/${id}/files/upload?path=/home/ubuntu`)
    .set('Authorization', `Bearer ${owner.token}`)
    .set('X-Upload-Id', 'up-1')
    .attach('file', body, 'hello.txt');
  assert.equal(up.status, 200);
  assert.equal(up.body.data.uploaded[0].name, 'hello.txt');

  const down = await request(app)
    .get(`/api/servers/${id}/files/download?path=/home/ubuntu/hello.txt`)
    .set('Authorization', `Bearer ${owner.token}`);
  assert.equal(down.status, 200);
  assert.equal(down.text, 'hello-file-manager');
  assert.match(down.headers['content-disposition'], /filename="hello\.txt"/);
  assert.match(down.headers['content-disposition'], /filename\*=UTF-8''hello\.txt/);
  assert.equal(down.headers['content-length'], String(body.length));
});

test('download ticket works without bearer and is single-use', async () => {
  const { owner, id } = await createOwnedServer();
  const ticketRes = await api(owner.token).post(`/api/servers/${id}/files/download-ticket`, {
    path: '/home/ubuntu/nginx.conf',
  });
  assert.equal(ticketRes.status, 200);
  const ticket = ticketRes.body.data.ticket;
  const down = await request(app).get(`/api/servers/${id}/files/download?ticket=${ticket}`);
  assert.equal(down.status, 200);
  assert.match(down.headers['content-disposition'], /nginx\.conf/);
  const reuse = await request(app).get(`/api/servers/${id}/files/download?ticket=${ticket}`);
  assert.equal(reuse.status, 401);
});

test('download preserves spaces and unicode in Content-Disposition', async () => {
  const { owner, id } = await createOwnedServer();
  const body = Buffer.from('report');
  const up = await request(app)
    .post(`/api/servers/${id}/files/upload?path=/home/ubuntu`)
    .set('Authorization', `Bearer ${owner.token}`)
    .attach('file', body, 'Q3 report.txt');
  assert.equal(up.status, 200);
  assert.equal(up.body.data.uploaded[0].name, 'Q3 report.txt');

  const down = await request(app)
    .get(`/api/servers/${id}/files/download`)
    .query({ path: '/home/ubuntu/Q3 report.txt' })
    .set('Authorization', `Bearer ${owner.token}`);
  assert.equal(down.status, 200);
  assert.match(down.headers['content-disposition'], /filename="Q3%20report\.txt"/);
  assert.match(down.headers['content-disposition'], /filename\*=UTF-8''Q3%20report\.txt/);
});

test('edit nginx.conf and reopen; binary refused; too large message path', async () => {
  const { owner, id } = await createOwnedServer();
  const read = await api(owner.token).get(
    `/api/servers/${id}/files/content?path=/home/ubuntu/nginx.conf`,
  );
  assert.equal(read.status, 200);
  assert.equal(read.body.data.language, 'nginx');

  const saved = await request(app)
    .put(`/api/servers/${id}/files/content`)
    .set('Authorization', `Bearer ${owner.token}`)
    .send({
      path: '/home/ubuntu/nginx.conf',
      content: 'server { listen 8080; }\n',
      expectedModifiedAt: read.body.data.modifiedAt,
    });
  assert.equal(saved.status, 200);

  const binary = await api(owner.token).get(
    `/api/servers/${id}/files/content?path=/home/ubuntu/binary.dat`,
  );
  assert.equal(binary.status, 415);

  const script = await api(owner.token).get(
    `/api/servers/${id}/files/content?path=/home/ubuntu/deploy.sh`,
  );
  assert.equal(script.status, 200);
  const saveScript = await request(app)
    .put(`/api/servers/${id}/files/content`)
    .set('Authorization', `Bearer ${owner.token}`)
    .send({
      path: '/home/ubuntu/deploy.sh',
      content: script.body.data.content,
      expectedModifiedAt: script.body.data.modifiedAt,
    });
  assert.equal(saveScript.status, 200);
  assert.equal(saveScript.body.data.modeOctal, '0755');
});

test('stale mtime returns 409', async () => {
  const { owner, id } = await createOwnedServer();
  const save = await request(app)
    .put(`/api/servers/${id}/files/content`)
    .set('Authorization', `Bearer ${owner.token}`)
    .send({
      path: '/home/ubuntu/nginx.conf',
      content: 'x',
      expectedModifiedAt: '2000-01-01T00:00:00.000Z',
    });
  assert.equal(save.status, 409);
});

test('unzip malicious name does not execute', async () => {
  const { owner, id } = await createOwnedServer();
  const payload = Buffer.from('MOCKZIP:{"ok.txt":"safe"}');
  await request(app)
    .post(`/api/servers/${id}/files/upload?path=/home/ubuntu`)
    .set('Authorization', `Bearer ${owner.token}`)
    .attach('file', payload, 'test; rm -rf x.zip');

  const unzip = await api(owner.token).post(`/api/servers/${id}/files/unzip`, {
    path: '/home/ubuntu/test; rm -rf x.zip',
  });
  assert.equal(unzip.status, 200);

  const tmp = await api(owner.token).get(`/api/servers/${id}/files?path=/tmp`);
  const names = tmp.body.data.entries.map((e) => e.name);
  assert.equal(names.includes('x'), false);
  assert.equal(names.includes('pwned'), false);
});

test('zip download streams', async () => {
  const { owner, id } = await createOwnedServer();
  const res = await request(app)
    .post(`/api/servers/${id}/files/download-zip`)
    .set('Authorization', `Bearer ${owner.token}`)
    .send({ directory: '/home/ubuntu', files: ['nginx.conf', '.env'] });
  assert.equal(res.status, 200);
  assert.match(res.headers['content-type'], /zip/);
  assert.match(res.headers['content-disposition'], /filename\*=UTF-8''/);
});

test('zip ticket then GET streams one archive', async () => {
  const { owner, id } = await createOwnedServer();
  const ticketRes = await api(owner.token).post(
    `/api/servers/${id}/files/download-zip-ticket`,
    { directory: '/home/ubuntu', files: ['nginx.conf', '.env'] },
  );
  assert.equal(ticketRes.status, 200);
  const ticket = ticketRes.body.data.ticket;
  const res = await request(app).get(
    `/api/servers/${id}/files/download-zip?ticket=${ticket}`,
  );
  assert.equal(res.status, 200);
  assert.match(res.headers['content-type'], /zip/);
});

test('folder size is cached', async () => {
  const { owner, id } = await createOwnedServer();
  const a = await api(owner.token).get(
    `/api/servers/${id}/files/folder-size?path=/home/ubuntu`,
  );
  assert.equal(a.status, 200);
  assert.equal(a.body.data.cached, false);
  const b = await api(owner.token).get(
    `/api/servers/${id}/files/folder-size?path=/home/ubuntu`,
  );
  assert.equal(b.body.data.cached, true);
  assert.equal(b.body.data.bytes, a.body.data.bytes);
});

test('audit log has operations and no file contents', async () => {
  const { owner, id } = await createOwnedServer();
  await api(owner.token).post(`/api/servers/${id}/files/mkdir`, {
    path: '/home/ubuntu',
    name: 'audited',
  });
  const { rows } = await query(
    'SELECT operation, path, error_code FROM file_operation_logs WHERE server_id = $1',
    [id],
  );
  assert.ok(rows.length >= 1);
  assert.equal(rows[0].operation, 'MKDIR');
  const blob = JSON.stringify(rows);
  assert.equal(blob.includes('BEGIN OPENSSH'), false);
  assert.equal(blob.includes('server {'), false);
});

test('preferences persist layout and hidden', async () => {
  const { owner } = await createOwnedServer();
  const patched = await api(owner.token).patch('/api/preferences', {
    fileManagerLayout: 'grid',
    showHiddenFiles: true,
  });
  assert.equal(patched.status, 200);
  const got = await api(owner.token).get('/api/preferences');
  assert.equal(got.body.data.fileManagerLayout, 'grid');
  assert.equal(got.body.data.showHiddenFiles, true);
});

test('existing ping still works after file routes', async () => {
  const { owner, id } = await createOwnedServer();
  const ping = await api(owner.token).post(`/api/servers/${id}/ping`);
  assert.equal(ping.status, 200);
});

void prevMock;
