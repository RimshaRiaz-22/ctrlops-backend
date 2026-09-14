import crypto from 'crypto';
import { Client } from 'ssh2';
import { mapSshError } from './sshError.service.js';
import { parseProxyCommand } from '../utils/parseProxyCommand.js';
import { createMockSshSession } from './mockSftp.service.js';

const READY_TIMEOUT = 30_000;

/** Disable Nagle so interactive PTY bytes flush immediately, like OpenSSH. */
function tuneSshLatency(conn) {
  try {
    conn.setNoDelay?.(true);
  } catch {
    /* mock clients and closed sockets have no TCP socket */
  }
}

function fingerprintSha256(keyBuffer) {
  return crypto.createHash('sha256').update(keyBuffer).digest('hex');
}

function detectKeyAlgorithm(keyBuffer) {
  if (!keyBuffer || keyBuffer.length < 5) return null;
  try {
    const len = keyBuffer.readUInt32BE(0);
    if (len > 0 && len < 64 && keyBuffer.length >= 4 + len) {
      return keyBuffer.subarray(4, 4 + len).toString('utf8');
    }
  } catch {
    // ignore
  }
  return null;
}

export function parseOsInfo(raw) {
  if (!raw) return null;

  const lines = raw.split('\n');
  let distro;
  let version;
  let arch;
  let pretty;

  for (const line of lines) {
    if (line.startsWith('PRETTY_NAME=')) {
      pretty = line.split('=')[1]?.replaceAll('"', '').trim();
    }
    if (line.startsWith('NAME=')) {
      distro = line.split('=')[1]?.replaceAll('"', '').trim();
    }
    if (line.startsWith('VERSION_ID=')) {
      version = line.split('=')[1]?.replaceAll('"', '').trim();
    }
  }

  const uname = lines[0] ?? '';
  const archMatch = uname.match(/\b(x86_64|amd64|aarch64|arm64|i686|armv7l)\b/);
  if (archMatch) arch = archMatch[1];

  if (!distro && pretty) distro = pretty.split(' ')[0];

  return {
    distro: distro ?? null,
    version: version ?? null,
    arch: arch ?? null,
    raw,
  };
}

function applyAuth(connectConfig, { privateKey, passphrase, password }) {
  if (password) {
    connectConfig.password = password;
  } else if (privateKey) {
    connectConfig.privateKey = privateKey;
    if (passphrase) connectConfig.passphrase = passphrase;
  }
}

function runReadySession(conn, { started, capture, finish }) {
  conn.on('ready', () => {
    conn.exec('uname -a && cat /etc/os-release 2>/dev/null', (err, stream) => {
      if (err) {
        return finish({
          ok: true,
          data: {
            hostKeyFingerprint: capture.fingerprint,
            hostKeyAlgorithm: capture.algorithm,
            osInfo: null,
            latencyMs: Date.now() - started,
          },
        });
      }

      let out = '';
      stream.on('data', (d) => {
        out += d.toString();
      });
      stream.stderr?.on('data', () => {});
      stream.on('close', () => {
        finish({
          ok: true,
          data: {
            hostKeyFingerprint: capture.fingerprint,
            hostKeyAlgorithm: capture.algorithm,
            osInfo: parseOsInfo(out),
            latencyMs: Date.now() - started,
          },
        });
      });
    });
  });

  conn.on('error', (err) => {
    finish({ ok: false, error: mapSshError(err) });
  });
}

export function verifyHostKey(storedFingerprint, keyBuffer) {
  const fingerprint = fingerprintSha256(keyBuffer);
  const algorithm = detectKeyAlgorithm(keyBuffer);
  if (!storedFingerprint) {
    return { ok: true, fingerprint, algorithm, tofu: true };
  }
  if (fingerprint !== storedFingerprint) {
    return { ok: false, fingerprint, algorithm };
  }
  return { ok: true, fingerprint, algorithm, tofu: false };
}

function makeHostVerifier(storedFingerprint, capture, finish) {
  return (keyBuffer) => {
    const result = verifyHostKey(storedFingerprint, keyBuffer);
    capture.algorithm = result.algorithm;
    if (!result.ok) {
      finish({
        ok: false,
        error: mapSshError({
          code: 'HOST_KEY_MISMATCH',
          message: 'Host key verification failed: mismatch',
        }),
      });
      return false;
    }
    capture.fingerprint = result.fingerprint;
    return true;
  };
}

function directConnect({
  host,
  port,
  username,
  privateKey,
  passphrase,
  password,
  storedFingerprint,
  started,
  finish,
}) {
  const conn = new Client();
  const capture = { fingerprint: storedFingerprint ?? null, algorithm: null };

  runReadySession(conn, { started, capture, finish: (result) => {
    try { conn.end(); } catch { /* ignore */ }
    finish(result);
  }});

  const connectConfig = {
    host,
    port: port ?? 22,
    username,
    readyTimeout: READY_TIMEOUT,
    hostVerifier: makeHostVerifier(storedFingerprint, capture, finish),
  };

  applyAuth(connectConfig, { privateKey, passphrase, password });

  try {
    conn.connect(connectConfig);
  } catch (err) {
    finish({ ok: false, error: mapSshError(err) });
  }
}

function connectViaBastion({
  host,
  port,
  username,
  privateKey,
  passphrase,
  password,
  storedFingerprint,
  storedBastionFingerprint,
  bastion,
  started,
  finish,
}) {
  const bastionConn = new Client();
  const targetConn = new Client();
  const capture = { fingerprint: storedFingerprint ?? null, algorithm: null };
  const bastionCapture = {
    fingerprint: storedBastionFingerprint ?? null,
    algorithm: null,
  };
  let settled = false;

  const safeFinish = (result) => {
    if (settled) return;
    settled = true;
    if (result?.ok && result.data) {
      result.data.bastionHostKeyFingerprint = bastionCapture.fingerprint;
      result.data.bastionHostKeyAlgorithm = bastionCapture.algorithm;
    }
    try { targetConn.end(); } catch { /* ignore */ }
    try { bastionConn.end(); } catch { /* ignore */ }
    finish(result);
  };

  runReadySession(targetConn, { started, capture, finish: safeFinish });

  bastionConn.on('error', (err) => {
    const mapped = mapSshError(err);
    safeFinish({
      ok: false,
      error: {
        ...mapped,
        message: `Could not connect to bastion (${bastion.host}): ${mapped.message}`,
        hint:
          mapped.hint ??
          'Check bastion IP, port, username, and that your key is authorized on the bastion.',
      },
    });
  });

  bastionConn.on('ready', () => {
    bastionConn.forwardOut('127.0.0.1', 0, host, port ?? 22, (err, stream) => {
      if (err) {
        return safeFinish({ ok: false, error: mapSshError(err) });
      }

      targetConn.on('error', (targetErr) => {
        safeFinish({ ok: false, error: mapSshError(targetErr) });
      });

      const targetConfig = {
        sock: stream,
        username,
        readyTimeout: READY_TIMEOUT,
        hostVerifier: makeHostVerifier(storedFingerprint, capture, safeFinish),
      };

      applyAuth(targetConfig, { privateKey, passphrase, password });

      try {
        targetConn.connect(targetConfig);
      } catch (connectErr) {
        safeFinish({ ok: false, error: mapSshError(connectErr) });
      }
    });
  });

  const bastionConfig = {
    host: bastion.host,
    port: bastion.port ?? 22,
    username: bastion.username,
    readyTimeout: READY_TIMEOUT,
    hostVerifier: makeHostVerifier(storedBastionFingerprint, bastionCapture, safeFinish),
  };

  applyAuth(bastionConfig, { privateKey, passphrase, password });

  try {
    bastionConn.connect(bastionConfig);
  } catch (err) {
    safeFinish({ ok: false, error: mapSshError(err) });
  }
}

/**
 * Test an SSH connection without persisting anything.
 * Resolves to { ok: true, data } or { ok: false, error }.
 */
export function testConnection(opts) {
  if (process.env.MOCK_SSH === 'true') {
    return mockTestConnection(opts);
  }
  return realTestConnection(opts);
}

function mockTestConnection({ privateKey, password }) {
  if (privateKey?.includes('INVALID_CRED') || password === 'wrong-password') {
    return Promise.resolve({
      ok: false,
      error: {
        code: 'AUTH_FAILED',
        message:
          'Authentication failed. Check the username and that this key is authorised on the server.',
        hint: "Confirm the public key is in ~/.ssh/authorized_keys for the username you entered.",
      },
    });
  }

  return Promise.resolve({
    ok: true,
    data: {
      hostKeyFingerprint: 'mock-host-fingerprint',
      hostKeyAlgorithm: 'ssh-ed25519',
      osInfo: {
        distro: 'Ubuntu',
        version: '24.04',
        arch: 'x86_64',
        raw: 'Linux mock',
      },
      latencyMs: 5,
    },
  });
}

function realTestConnection({
  host,
  port,
  username,
  privateKey,
  passphrase,
  password,
  storedFingerprint,
  storedBastionFingerprint,
  proxyCommand,
}) {
  const started = Date.now();
  const bastion = parseProxyCommand(proxyCommand);

  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const params = {
      host,
      port,
      username,
      privateKey,
      passphrase,
      password,
      storedFingerprint,
      storedBastionFingerprint,
      started,
      finish,
    };

    if (bastion) {
      connectViaBastion({ ...params, bastion });
    } else {
      directConnect(params);
    }
  });
}

/**
 * Open an SSH+SFTP session and keep it alive for the connection pool.
 * Does not run OS detection and does not call conn.end() on success.
 */
export function connectAndKeep(opts) {
  if (process.env.MOCK_SSH === 'true') {
    return mockConnectAndKeep(opts);
  }
  return realConnectAndKeep(opts);
}

function mockConnectAndKeep(opts) {
  if (opts.privateKey?.includes('INVALID_CRED') || opts.password === 'wrong-password') {
    return Promise.reject(
      Object.assign(new Error('Authentication failed'), { code: 'AUTH_FAILED' }),
    );
  }
  const { conn, sftp } = createMockSshSession({ username: opts.username ?? 'ubuntu' });
  return Promise.resolve({
    conn,
    sftp,
    close: () => {
      try {
        conn.end();
      } catch {
        /* ignore */
      }
    },
  });
}

function realConnectAndKeep({
  host,
  port,
  username,
  privateKey,
  passphrase,
  password,
  storedFingerprint,
  storedBastionFingerprint,
  proxyCommand,
}) {
  const bastion = parseProxyCommand(proxyCommand);
  if (bastion) {
    return connectKeepViaBastion({
      host,
      port,
      username,
      privateKey,
      passphrase,
      password,
      storedFingerprint,
      storedBastionFingerprint,
      bastion,
    });
  }
  return connectKeepDirect({
    host,
    port,
    username,
    privateKey,
    passphrase,
    password,
    storedFingerprint,
  });
}

function connectKeepDirect({
  host,
  port,
  username,
  privateKey,
  passphrase,
  password,
  storedFingerprint,
}) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    const capture = { fingerprint: storedFingerprint ?? null, algorithm: null };
    let settled = false;

    const fail = (err) => {
      if (settled) return;
      settled = true;
      try {
        conn.end();
      } catch {
        /* ignore */
      }
      reject(err);
    };

    const finish = (result) => {
      if (result?.ok === false) {
        fail(Object.assign(new Error(result.error?.message ?? 'SSH failed'), result.error));
      }
    };

    conn.on('ready', () => {
      tuneSshLatency(conn);
      conn.sftp((err, sftp) => {
        if (err) return fail(err);
        if (settled) return;
        settled = true;
        resolve({
          conn,
          sftp,
          close: () => {
            try {
              conn.end();
            } catch {
              /* ignore */
            }
          },
        });
      });
    });

    conn.on('error', (err) => fail(err));

    const connectConfig = {
      host,
      port: port ?? 22,
      username,
      readyTimeout: READY_TIMEOUT,
      hostVerifier: makeHostVerifier(storedFingerprint, capture, finish),
    };
    applyAuth(connectConfig, { privateKey, passphrase, password });

    try {
      conn.connect(connectConfig);
    } catch (err) {
      fail(err);
    }
  });
}

function connectKeepViaBastion({
  host,
  port,
  username,
  privateKey,
  passphrase,
  password,
  storedFingerprint,
  storedBastionFingerprint,
  bastion,
}) {
  return new Promise((resolve, reject) => {
    const bastionConn = new Client();
    const targetConn = new Client();
    const capture = { fingerprint: storedFingerprint ?? null, algorithm: null };
    const bastionCapture = {
      fingerprint: storedBastionFingerprint ?? null,
      algorithm: null,
    };
    let settled = false;

    const fail = (err) => {
      if (settled) return;
      settled = true;
      try {
        targetConn.end();
      } catch {
        /* ignore */
      }
      try {
        bastionConn.end();
      } catch {
        /* ignore */
      }
      reject(err);
    };

    const finish = (result) => {
      if (result?.ok === false) {
        fail(Object.assign(new Error(result.error?.message ?? 'SSH failed'), result.error));
      }
    };

    bastionConn.on('error', (err) => fail(err));

    bastionConn.on('ready', () => {
      tuneSshLatency(bastionConn);
      bastionConn.forwardOut('127.0.0.1', 0, host, port ?? 22, (err, stream) => {
        if (err) return fail(err);

        targetConn.on('error', (targetErr) => fail(targetErr));
        targetConn.on('ready', () => {
          tuneSshLatency(targetConn);
          targetConn.sftp((sftpErr, sftp) => {
            if (sftpErr) return fail(sftpErr);
            if (settled) return;
            settled = true;
            resolve({
              conn: targetConn,
              sftp,
              close: () => {
                try {
                  targetConn.end();
                } catch {
                  /* ignore */
                }
                try {
                  bastionConn.end();
                } catch {
                  /* ignore */
                }
              },
            });
          });
        });

        const targetConfig = {
          sock: stream,
          username,
          readyTimeout: READY_TIMEOUT,
          hostVerifier: makeHostVerifier(storedFingerprint, capture, finish),
        };
        applyAuth(targetConfig, { privateKey, passphrase, password });
        try {
          targetConn.connect(targetConfig);
        } catch (connectErr) {
          fail(connectErr);
        }
      });
    });

    const bastionConfig = {
      host: bastion.host,
      port: bastion.port ?? 22,
      username: bastion.username,
      readyTimeout: READY_TIMEOUT,
      hostVerifier: makeHostVerifier(storedBastionFingerprint, bastionCapture, finish),
    };
    applyAuth(bastionConfig, { privateKey, passphrase, password });

    try {
      bastionConn.connect(bastionConfig);
    } catch (err) {
      fail(err);
    }
  });
}

export const sshClient = {
  testConnection,
  connectAndKeep,
};
