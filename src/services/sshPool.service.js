import { promisify } from 'util';
import { AppError } from '../middleware/errorHandler.js';
import { env } from '../config/env.js';
import * as cryptoService from './crypto.service.js';
import { sshClient } from './ssh.service.js';
import * as serverRepo from '../repositories/server.repository.js';
import { sshErrorToAppError } from './sshError.service.js';

const pool = new Map();
const inflight = new Map();
let idleTimeoutMs = env.SSH_POOL_IDLE_MS;
const MAX_PER_USER = env.SSH_POOL_MAX_PER_USER;

function userKeyPrefix(userId) {
  return `${userId}:`;
}

function poolKey(userId, serverId) {
  return `${userId}:${serverId}`;
}

function countForUser(userId) {
  const prefix = userKeyPrefix(userId);
  let n = 0;
  for (const key of pool.keys()) {
    if (key.startsWith(prefix)) n += 1;
  }
  return n;
}

function isBusy(entry) {
  return (
    entry.refCount > 0 ||
    (entry.activeSessions ?? 0) > 0 ||
    (entry.activeMonitors ?? 0) > 0
  );
}

function scheduleEviction(key) {
  const timer = setTimeout(() => {
    const entry = pool.get(key);
    if (!entry) return;
    if (isBusy(entry)) {
      entry.idleTimer = scheduleEviction(key);
      return;
    }
    evict(key);
  }, idleTimeoutMs);
  timer.unref?.();
  return timer;
}

function evict(key) {
  const entry = pool.get(key);
  if (!entry) return;
  clearTimeout(entry.idleTimer);
  pool.delete(key);
  try {
    entry.close?.();
  } catch {
    /* ignore */
  }
}

function wireHealth(key, conn) {
  const markUnhealthy = () => {
    const entry = pool.get(key);
    if (entry) entry.healthy = false;
  };
  conn.on?.('error', markUnhealthy);
  conn.on?.('close', markUnhealthy);
}

async function createEntry(userId, serverId) {
  if (countForUser(userId) >= MAX_PER_USER) {
    throw new AppError(
      'TOO_MANY_CONNECTIONS',
      429,
      `You can keep at most ${MAX_PER_USER} servers connected at once.`,
    );
  }

  const server = await serverRepo.findOwned(serverId, userId);
  if (!server) {
    throw new AppError('NOT_FOUND', 404, 'Server not found.');
  }

  const privateKeyOrPassword = cryptoService.decrypt({
    ciphertext: server.credCiphertext,
    iv: server.credIv,
    authTag: server.credAuthTag,
  });
  const passphrase = server.passCiphertext
    ? cryptoService.decrypt({
        ciphertext: server.passCiphertext,
        iv: server.passIv,
        authTag: server.passAuthTag,
      })
    : undefined;

  try {
    const session = await sshClient.connectAndKeep({
      host: server.host,
      port: server.port,
      username: server.username,
      privateKey: server.authMethod === 'PASSWORD' ? undefined : privateKeyOrPassword,
      password: server.authMethod === 'PASSWORD' ? privateKeyOrPassword : undefined,
      passphrase,
      storedFingerprint: server.hostKeyFingerprint,
      storedBastionFingerprint: server.bastionHostKeyFingerprint,
      proxyCommand: server.proxyCommand,
    });

    const key = poolKey(userId, serverId);
    const entry = {
      conn: session.conn,
      sftp: session.sftp,
      close: session.close,
      healthy: true,
      refCount: 0,
      activeSessions: 0,
      activeMonitors: 0,
      idleTimer: scheduleEviction(key),
      username: server.username,
    };
    wireHealth(key, session.conn);
    pool.set(key, entry);
    return entry;
  } catch (err) {
    throw sshErrorToAppError(err);
  }
}

async function ensureEntry(userId, serverId) {
  const key = poolKey(userId, serverId);
  const existing = pool.get(key);

  if (existing?.conn && existing.healthy) {
    return existing;
  }

  if (existing) {
    evict(key);
  }

  const pending = inflight.get(key);
  if (pending) return pending;

  const promise = createEntry(userId, serverId).finally(() => {
    inflight.delete(key);
  });
  inflight.set(key, promise);
  return promise;
}

export async function acquire(userId, serverId) {
  const key = poolKey(userId, serverId);
  const entry = await ensureEntry(userId, serverId);
  clearTimeout(entry.idleTimer);
  entry.idleTimer = scheduleEviction(key);
  entry.refCount += 1;
  return entry;
}

export function release(userId, serverId) {
  const key = poolKey(userId, serverId);
  const entry = pool.get(key);
  if (!entry) return;
  entry.refCount = Math.max(0, entry.refCount - 1);
  clearTimeout(entry.idleTimer);
  entry.idleTimer = scheduleEviction(key);
}

/** Pin the pooled SSH connection for a live terminal. Does not touch refCount. */
export async function pinSession(userId, serverId) {
  const key = poolKey(userId, serverId);
  const entry = await ensureEntry(userId, serverId);
  clearTimeout(entry.idleTimer);
  entry.activeSessions = (entry.activeSessions ?? 0) + 1;
  entry.idleTimer = scheduleEviction(key);
  return entry;
}

export function unpinSession(userId, serverId) {
  const key = poolKey(userId, serverId);
  const entry = pool.get(key);
  if (!entry) return;
  entry.activeSessions = Math.max(0, (entry.activeSessions ?? 0) - 1);
  clearTimeout(entry.idleTimer);
  entry.idleTimer = scheduleEviction(key);
}

/** Pin the pooled SSH connection for live metrics. Does not touch refCount. */
export async function pinMonitor(userId, serverId) {
  const key = poolKey(userId, serverId);
  const entry = await ensureEntry(userId, serverId);
  clearTimeout(entry.idleTimer);
  entry.activeMonitors = (entry.activeMonitors ?? 0) + 1;
  entry.idleTimer = scheduleEviction(key);
  return entry;
}

export function unpinMonitor(userId, serverId) {
  const key = poolKey(userId, serverId);
  const entry = pool.get(key);
  if (!entry) return;
  entry.activeMonitors = Math.max(0, (entry.activeMonitors ?? 0) - 1);
  clearTimeout(entry.idleTimer);
  entry.idleTimer = scheduleEviction(key);
}

export function peek(userId, serverId) {
  return pool.get(poolKey(userId, serverId)) ?? null;
}

export function poolSize() {
  return pool.size;
}

export function inspectPoolForTests(userId, serverId) {
  return pool.get(poolKey(userId, serverId)) ?? null;
}

export function setIdleTimeoutForTests(ms) {
  idleTimeoutMs = ms;
}

export function resetPoolForTests() {
  for (const key of [...pool.keys()]) evict(key);
  inflight.clear();
  idleTimeoutMs = env.SSH_POOL_IDLE_MS;
}

export async function withSftp(userId, serverId, fn) {
  const entry = await acquire(userId, serverId);
  try {
    return await fn(entry);
  } finally {
    release(userId, serverId);
  }
}

export function promisifySftp(sftp, method) {
  return promisify(sftp[method].bind(sftp));
}
