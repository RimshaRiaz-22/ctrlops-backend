import { AppError } from '../middleware/errorHandler.js';
import {
  testConnectionSchema,
  createServerSchema,
} from '../schemas/server.schema.js';
import { assertSshTargetsAllowed } from '../utils/ipGuard.js';
import { sshClient } from '../services/ssh.service.js';
import * as cryptoService from '../services/crypto.service.js';
import * as serverRepo from '../repositories/server.repository.js';

function toPublicServer(row) {
  if (!row) return null;
  return {
    ...row,
    health: row.health ?? null,
    osInfo:
      row.osDistro || row.osVersion || row.osArch
        ? {
            distro: row.osDistro ?? undefined,
            version: row.osVersion ?? undefined,
            arch: row.osArch ?? undefined,
          }
        : null,
  };
}

export async function list(req, res, next) {
  try {
    const servers = await serverRepo.listServers({
      userId: req.user.id,
      search: req.query.search,
      type: req.query.type,
      favorite: req.query.favorite,
    });
    res.json({ ok: true, data: servers.map(toPublicServer) });
  } catch (err) {
    next(err);
  }
}

export async function getOne(req, res, next) {
  try {
    const server = await serverRepo.getServerById({
      userId: req.user.id,
      id: req.params.id,
    });
    if (!server) {
      throw new AppError('NOT_FOUND', 404, 'Server not found.');
    }
    res.json({ ok: true, data: toPublicServer(server) });
  } catch (err) {
    next(err);
  }
}

export async function testConnection(req, res, next) {
  try {
    const blocked = await assertSshTargetsAllowed(req.body.host, {
      proxyCommand: req.body.proxyCommand,
    });
    if (blocked) {
      return res.status(200).json({ ok: false, error: blocked });
    }

    const result = await sshClient.testConnection({
      host: req.body.host,
      port: req.body.port,
      username: req.body.username,
      privateKey: req.body.privateKey,
      passphrase: req.body.passphrase,
      password: req.body.password,
      proxyCommand: req.body.proxyCommand,
    });

    return res.status(200).json(result);
  } catch (err) {
    next(err);
  }
}

export async function create(req, res, next) {
  try {
    const blocked = await assertSshTargetsAllowed(req.body.host, {
      proxyCommand: req.body.proxyCommand,
    });
    if (blocked) {
      return res.status(200).json({ ok: false, error: blocked });
    }

    const result = await sshClient.testConnection({
      host: req.body.host,
      port: req.body.port,
      username: req.body.username,
      privateKey: req.body.privateKey,
      passphrase: req.body.passphrase,
      password: req.body.password,
      proxyCommand: req.body.proxyCommand,
    });

    if (!result.ok) {
      return res.status(200).json(result);
    }

    const plaintext =
      req.body.authMethod === 'PASSWORD'
        ? req.body.password
        : req.body.privateKey;

    const encrypted = cryptoService.encrypt(plaintext);
    const encryptedPass = req.body.passphrase
      ? cryptoService.encrypt(req.body.passphrase)
      : null;

    let server;
    try {
      server = await serverRepo.createServer({
        userId: req.user.id,
        name: req.body.name,
        type: req.body.type ?? 'OTHER',
        host: req.body.host,
        port: req.body.port,
        username: req.body.username,
        authMethod: req.body.authMethod,
        credCiphertext: encrypted.ciphertext,
        credIv: encrypted.iv,
        credAuthTag: encrypted.authTag,
        credKeyVersion: encrypted.keyVersion,
        passCiphertext: encryptedPass?.ciphertext ?? null,
        passIv: encryptedPass?.iv ?? null,
        passAuthTag: encryptedPass?.authTag ?? null,
        passKeyVersion: encryptedPass?.keyVersion ?? null,
        proxyCommand: req.body.proxyCommand ?? null,
        hostKeyFingerprint: result.data.hostKeyFingerprint,
        hostKeyAlgorithm: result.data.hostKeyAlgorithm,
        bastionHostKeyFingerprint: result.data.bastionHostKeyFingerprint ?? null,
        bastionHostKeyAlgorithm: result.data.bastionHostKeyAlgorithm ?? null,
        osRaw: result.data.osInfo?.raw ?? null,
        osDistro: result.data.osInfo?.distro ?? null,
        osVersion: result.data.osInfo?.version ?? null,
        osArch: result.data.osInfo?.arch ?? null,
        status: 'ONLINE',
      });
    } catch (err) {
      if (err.code === '23505') {
        throw new AppError(
          'DUPLICATE_SERVER',
          409,
          'A server with this host, port, and username already exists.',
        );
      }
      throw err;
    }

    res.status(201).json({ ok: true, data: toPublicServer(server) });
  } catch (err) {
    next(err);
  }
}

export async function update(req, res, next) {
  try {
    const server = await serverRepo.updateServer({
      userId: req.user.id,
      id: req.params.id,
      name: req.body.name,
      type: req.body.type,
      isFavorite: req.body.isFavorite,
    });
    if (!server) {
      throw new AppError('NOT_FOUND', 404, 'Server not found.');
    }
    res.json({ ok: true, data: toPublicServer(server) });
  } catch (err) {
    next(err);
  }
}

export async function remove(req, res, next) {
  try {
    const deleted = await serverRepo.deleteServer({
      userId: req.user.id,
      id: req.params.id,
    });
    if (!deleted) {
      throw new AppError('NOT_FOUND', 404, 'Server not found.');
    }
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
}

export async function ping(req, res, next) {
  try {
    const row = await serverRepo.getServerCredsForPing({
      userId: req.user.id,
      id: req.params.id,
    });
    if (!row) {
      throw new AppError('NOT_FOUND', 404, 'Server not found.');
    }

    const blocked = await assertSshTargetsAllowed(row.host, {
      proxyCommand: row.proxyCommand,
    });
    if (blocked) {
      return res.status(200).json({ ok: false, error: blocked });
    }

    const privateKeyOrPassword = cryptoService.decrypt({
      ciphertext: row.credCiphertext,
      iv: row.credIv,
      authTag: row.credAuthTag,
    });

    const passphrase = row.passCiphertext
      ? cryptoService.decrypt({
          ciphertext: row.passCiphertext,
          iv: row.passIv,
          authTag: row.passAuthTag,
        })
      : undefined;

    const result = await sshClient.testConnection({
      host: row.host,
      port: row.port,
      username: row.username,
      privateKey: row.authMethod === 'PASSWORD' ? undefined : privateKeyOrPassword,
      password: row.authMethod === 'PASSWORD' ? privateKeyOrPassword : undefined,
      passphrase,
      storedFingerprint: row.hostKeyFingerprint,
      storedBastionFingerprint: row.bastionHostKeyFingerprint,
      proxyCommand: row.proxyCommand,
    });

    const updated = await serverRepo.updateServerStatus({
      userId: req.user.id,
      id: row.id,
      status: result.ok ? 'ONLINE' : 'OFFLINE',
      lastError: result.ok ? null : result.error?.message,
      osInfo: result.ok ? result.data.osInfo : null,
      bastionHostKeyFingerprint: result.ok
        ? result.data?.bastionHostKeyFingerprint
        : null,
      bastionHostKeyAlgorithm: result.ok
        ? result.data?.bastionHostKeyAlgorithm
        : null,
    });

    if (!result.ok) {
      return res.status(200).json({ ok: false, error: result.error, data: updated });
    }

    res.json({ ok: true, data: toPublicServer(updated) });
  } catch (err) {
    next(err);
  }
}

export { testConnectionSchema, createServerSchema };
