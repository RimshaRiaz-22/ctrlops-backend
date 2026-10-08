import request from 'supertest';
import app from '../../src/app.js';
import { sshClient, testConnection } from '../../src/services/ssh.service.js';

export const FAKE_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDummyKeyForTestsOnlyNotRealAAAAAAAAAAAAAAAtzc2gtZWQyNTUxOQ
AAACDummyKeyForTestsOnlyNotReal
-----END OPENSSH PRIVATE KEY-----`;

export function mockSshOk(extra = {}) {
  sshClient.testConnection = async () => ({
    ok: true,
    data: {
      hostKeyFingerprint: 'fp-test',
      hostKeyAlgorithm: 'ssh-ed25519',
      osInfo: {
        distro: 'Ubuntu',
        version: '24.04',
        arch: 'x86_64',
        raw: 'Linux',
      },
      latencyMs: 1,
      ...extra,
    },
  });
}

export function mockSshFail(error) {
  sshClient.testConnection = async () => ({
    ok: false,
    error,
  });
}

export function restoreSsh() {
  sshClient.testConnection = testConnection;
}

export async function registerUser(email) {
  const unique =
    email ?? `u_${Date.now()}_${Math.random().toString(16).slice(2)}@test.local`;
  const res = await request(app)
    .post('/api/auth/register')
    .send({ email: unique, password: 'password123' });

  if (res.status !== 201 || !res.body.accessToken) {
    throw new Error(`register failed: ${JSON.stringify(res.body)}`);
  }

  return {
    email: unique,
    token: res.body.accessToken,
    user: res.body.user,
  };
}

export function api(token) {
  return {
    get: (url) =>
      request(app).get(url).set('Authorization', `Bearer ${token}`),
    post: (url, body) =>
      request(app).post(url).set('Authorization', `Bearer ${token}`).send(body),
    patch: (url, body) =>
      request(app).patch(url).set('Authorization', `Bearer ${token}`).send(body),
    delete: (url) =>
      request(app).delete(url).set('Authorization', `Bearer ${token}`),
  };
}

export function serverPayload(overrides = {}) {
  return {
    name: 'test-box',
    type: 'DEVELOPMENT',
    host: '8.8.8.8',
    port: 22,
    username: 'ubuntu',
    authMethod: 'KEY',
    privateKey: FAKE_KEY,
    ...overrides,
  };
}
