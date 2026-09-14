import path from 'path';
import { randomUUID } from 'crypto';
import busboy from 'busboy';
import mime from 'mime-types';
import { env } from '../config/env.js';
import { AppError } from '../middleware/errorHandler.js';
import { safePath } from '../utils/safePath.js';
import { sanitizeFilename } from '../utils/sanitizeFilename.js';
import { attachmentDisposition } from '../utils/contentDisposition.js';
import { isDirMode } from '../utils/posixMode.js';
import { withSftp } from '../services/sshPool.service.js';
import * as fileOps from '../services/fileOps.service.js';
import * as shellOps from '../services/shellOps.service.js';
import * as progressStore from '../services/progressStore.js';
import * as folderSizeCache from '../services/folderSizeCache.js';
import { issueTicket } from '../services/downloadTicket.service.js';
import { logSafe } from '../repositories/fileAudit.repository.js';
import { mapSftpError } from '../services/fileError.service.js';

function serverIdOf(req) {
  return req.params.serverId ?? req.params.id;
}

export async function list(req, res, next) {
  try {
    const data = await withSftp(req.user.id, serverIdOf(req), async ({ sftp }) => {
      const dir = req.query.path
        ? safePath(req.query.path)
        : await fileOps.resolveDefaultPath(sftp);
      return fileOps.listDirectory(sftp, dir);
    });
    res.json({ ok: true, data });
  } catch (err) {
    next(err);
  }
}

export async function upload(req, res, next) {
  const uploadId = req.get('x-upload-id') || randomUUID();
  const targetDir = safePath(req.query.path || '/');
  progressStore.createSession(uploadId);

  const uploaded = [];
  const failed = [];
  let aborted = false;
  const pendingUnlinks = [];

  const finish = async (status = 200) => {
    progressStore.completeSession(uploadId, {
      uploaded: uploaded.length,
      failed: failed.length,
    });
    res.status(status).json({ ok: true, data: { uploaded, failed } });
  };

  try {
    await withSftp(req.user.id, serverIdOf(req), async ({ sftp }) => {
      await new Promise((resolve, reject) => {
        const bb = busboy({ headers: req.headers, limits: { files: 500 } });
        const jobs = [];

        req.on('aborted', () => {
          aborted = true;
          progressStore.cancelSession(uploadId);
          req.unpipe(bb);
          bb.destroy();
        });

        bb.on('file', (_name, fileStream, info) => {
          const job = (async () => {
            let filename;
            let remotePath;
            try {
              const relative = info.filename?.replaceAll('\\', '/') ?? '';
              const parts = relative.split('/').filter(Boolean).map(sanitizeFilename);
              filename = parts[parts.length - 1] ?? sanitizeFilename(info.filename || 'upload');
              const dirParts = parts.slice(0, -1);
              let destDir = targetDir;
              if (dirParts.length) {
                destDir = path.posix.join(targetDir, ...dirParts);
                await fileOps.mkdirp(sftp, destDir);
              }
              remotePath = path.posix.join(destDir, filename);
              pendingUnlinks.push(remotePath);

              const writeStream = fileOps.createWriteStream(sftp, remotePath);
              let transferred = 0;
              let lastEmit = 0;

              const onAbort = () => {
                fileStream.unpipe(writeStream);
                writeStream.destroy();
                fileStream.destroy();
              };
              req.on('aborted', onAbort);

              await new Promise((resOk, resErr) => {
                fileStream.on('data', (chunk) => {
                  transferred += chunk.length;
                  if (transferred > env.MAX_UPLOAD_BYTES) {
                    fileStream.unpipe(writeStream);
                    writeStream.destroy();
                    fileStream.destroy();
                    return resErr(
                      new AppError(
                        'FILE_TOO_LARGE',
                        413,
                        `File exceeds the ${env.MAX_UPLOAD_BYTES} byte upload limit.`,
                      ),
                    );
                  }
                  const now = Date.now();
                  if (now - lastEmit > 250 || transferred % (1024 * 1024) < chunk.length) {
                    lastEmit = now;
                    progressStore.emit(uploadId, 'progress', {
                      file: filename,
                      transferred,
                      total: Number(info.expectedSize) || null,
                      percent:
                        info.expectedSize
                          ? Math.min(100, Math.round((transferred / info.expectedSize) * 100))
                          : null,
                    });
                  }
                });
                fileStream.pipe(writeStream);
                writeStream.on('close', resOk);
                writeStream.on('error', resErr);
                fileStream.on('error', resErr);
              });

              if (aborted) {
                await fileOps.unlink(sftp, remotePath);
                return;
              }

              progressStore.emit(uploadId, 'file-complete', { file: filename });
              uploaded.push({ name: filename, size: transferred, path: remotePath });
              await logSafe({
                userId: req.user.id,
                serverId: serverIdOf(req),
                operation: 'UPLOAD',
                path: remotePath,
                fileSize: transferred,
                success: true,
              });
            } catch (err) {
              if (remotePath) await fileOps.unlink(sftp, remotePath);
              failed.push({
                name: filename ?? info.filename,
                error: err.message ?? 'Upload failed',
              });
              await logSafe({
                userId: req.user.id,
                serverId: serverIdOf(req),
                operation: 'UPLOAD',
                path: remotePath ?? targetDir,
                success: false,
                errorCode: err.code ?? 'UPLOAD_FAILED',
              });
              if (err instanceof AppError && err.statusCode === 413) throw err;
            }
          })();
          jobs.push(job);
        });

        bb.on('error', (err) => {
          if (aborted || err?.message === 'Unexpected end of form') {
            aborted = true;
            resolve();
            return;
          }
          reject(err);
        });
        bb.on('finish', async () => {
          try {
            await Promise.all(jobs);
            if (aborted) {
              await Promise.all(pendingUnlinks.map((p) => fileOps.unlink(sftp, p)));
            }
            resolve();
          } catch (err) {
            reject(err);
          }
        });

        req.pipe(bb);
      });
    });

    if (aborted && !res.headersSent) {
      progressStore.cancelSession(uploadId);
      return res.status(499).json({
        ok: false,
        error: { code: 'UPLOAD_CANCELLED', message: 'Upload cancelled.' },
      });
    }
    if (!res.headersSent) await finish();
  } catch (err) {
    if (aborted || err?.message === 'Unexpected end of form') {
      if (!res.headersSent) {
        progressStore.cancelSession(uploadId);
        return res.status(499).json({
          ok: false,
          error: { code: 'UPLOAD_CANCELLED', message: 'Upload cancelled.' },
        });
      }
      return;
    }
    next(err);
  }
}

export async function progress(req, res, next) {
  try {
    const uploadId = req.query.uploadId;
    if (!uploadId) throw new AppError('VALIDATION_ERROR', 400, 'uploadId is required.');

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();

    const send = (event, data) => {
      res.write(`event: ${event}\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    const unsubscribe = progressStore.subscribe(uploadId, (event, data) => {
      send(event, data);
      if (event === 'complete' || event === 'cancelled' || event === 'error') {
        clearInterval(ping);
        res.end();
      }
    });

    const ping = setInterval(() => {
      res.write(': ping\n\n');
    }, 15_000);

    req.on('close', () => {
      clearInterval(ping);
      unsubscribe();
    });
  } catch (err) {
    next(err);
  }
}

export async function createDownloadTicket(req, res, next) {
  try {
    const remotePath = safePath(req.body.path);
    const basename = path.posix.basename(remotePath);
    await withSftp(req.user.id, serverIdOf(req), async ({ sftp }) => {
      const attrs = await fileOps.statPath(sftp, remotePath);
      if (isDirMode(attrs.mode)) {
        throw new AppError('NOT_A_FILE', 400, 'Right-click a file to download, not a folder.');
      }
    });
    const ticket = issueTicket({
      kind: 'file',
      userId: req.user.id,
      serverId: serverIdOf(req),
      path: remotePath,
    });
    res.json({ ok: true, data: { ticket, filename: basename } });
  } catch (err) {
    next(err);
  }
}

export async function createZipDownloadTicket(req, res, next) {
  try {
    const directory = safePath(req.body.directory);
    const files = req.body.files;
    await withSftp(req.user.id, serverIdOf(req), async ({ conn }) => {
      await shellOps.assertZipInstalled(conn);
    });
    const ticket = issueTicket({
      kind: 'zip',
      userId: req.user.id,
      serverId: serverIdOf(req),
      directory,
      files,
    });
    res.json({
      ok: true,
      data: { ticket, filename: shellOps.zipFilename(directory) },
    });
  } catch (err) {
    next(err);
  }
}

export async function download(req, res, next) {
  try {
    const remotePath = safePath(req.downloadTicket?.path ?? req.query.path);
    await withSftp(req.user.id, serverIdOf(req), async ({ sftp }) => {
      const attrs = await fileOps.statPath(sftp, remotePath);
      if (isDirMode(attrs.mode)) {
        throw new AppError('NOT_A_FILE', 400, 'Right-click a file to download, not a folder.');
      }
      const basename = path.posix.basename(remotePath);
      const type = mime.lookup(basename) || 'application/octet-stream';
      res.setHeader('Content-Type', type);
      res.setHeader('Content-Disposition', attachmentDisposition(basename));
      res.setHeader('Content-Length', attrs.size);
      res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
      await logSafe({
        userId: req.user.id,
        serverId: serverIdOf(req),
        operation: 'DOWNLOAD',
        path: remotePath,
        fileSize: attrs.size,
        success: true,
      });
      await new Promise((resolve, reject) => {
        const stream = fileOps.createReadStream(sftp, remotePath);
        stream.on('error', reject);
        stream.on('end', resolve);
        stream.pipe(res);
      });
    });
  } catch (err) {
    next(err);
  }
}

export async function downloadZip(req, res, next) {
  try {
    const directory = safePath(req.downloadTicket?.directory ?? req.body?.directory);
    const files = req.downloadTicket?.files ?? req.body?.files;
    if (!directory || !Array.isArray(files) || files.length === 0) {
      throw new AppError('VALIDATION_ERROR', 400, 'Select at least one file to zip.');
    }
    const name = shellOps.zipFilename(directory);
    await withSftp(req.user.id, serverIdOf(req), async ({ conn }) => {
      await shellOps.assertZipInstalled(conn);
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', attachmentDisposition(name));
      res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
      await shellOps.zipDownload(conn, directory, files, res);
    });
    await logSafe({
      userId: req.user.id,
      serverId: serverIdOf(req),
      operation: 'ZIP_DOWNLOAD',
      path: directory,
      success: true,
    });
  } catch (err) {
    await logSafe({
      userId: req.user.id,
      serverId: serverIdOf(req),
      operation: 'ZIP_DOWNLOAD',
      path: req.downloadTicket?.directory ?? req.body?.directory ?? '',
      success: false,
      errorCode: err.code ?? 'ZIP_FAILED',
    });
    next(err);
  }
}

export async function getContent(req, res, next) {
  try {
    const remotePath = safePath(req.query.path);
    const data = await withSftp(req.user.id, serverIdOf(req), ({ sftp }) =>
      fileOps.readFileLimited(sftp, remotePath),
    );
    res.json({ ok: true, data });
  } catch (err) {
    next(err);
  }
}

export async function putContent(req, res, next) {
  try {
    const remotePath = safePath(req.body.path);
    const data = await withSftp(req.user.id, serverIdOf(req), ({ sftp }) =>
      fileOps.atomicWrite(sftp, remotePath, req.body.content, {
        expectedModifiedAt: req.body.expectedModifiedAt,
        force: req.body.force,
      }),
    );
    await logSafe({
      userId: req.user.id,
      serverId: serverIdOf(req),
      operation: 'EDIT',
      path: remotePath,
      fileSize: Buffer.byteLength(req.body.content, 'utf8'),
      success: true,
    });
    res.json({ ok: true, data });
  } catch (err) {
    await logSafe({
      userId: req.user.id,
      serverId: serverIdOf(req),
      operation: 'EDIT',
      path: req.body?.path ?? '',
      success: false,
      errorCode: err.code ?? 'EDIT_FAILED',
    });
    next(err);
  }
}

export async function mkdir(req, res, next) {
  try {
    const dir = safePath(req.body.path);
    const name = req.body.name;
    const remotePath = path.posix.join(dir, name);
    await withSftp(req.user.id, serverIdOf(req), ({ sftp }) => fileOps.mkdir(sftp, remotePath));
    await logSafe({
      userId: req.user.id,
      serverId: serverIdOf(req),
      operation: 'MKDIR',
      path: remotePath,
      success: true,
    });
    res.json({ ok: true, data: { path: remotePath } });
  } catch (err) {
    next(err);
  }
}

export async function rename(req, res, next) {
  try {
    const from = safePath(req.body.path);
    const dir = path.posix.dirname(from);
    const to = path.posix.join(dir, req.body.newName);
    await withSftp(req.user.id, serverIdOf(req), ({ sftp }) => fileOps.rename(sftp, from, to));
    await logSafe({
      userId: req.user.id,
      serverId: serverIdOf(req),
      operation: 'RENAME',
      path: `${from} -> ${to}`,
      success: true,
    });
    res.json({ ok: true, data: { path: to } });
  } catch (err) {
    next(err);
  }
}

export async function remove(req, res, next) {
  const results = [];
  try {
    await withSftp(req.user.id, serverIdOf(req), async ({ sftp }) => {
      for (const p of req.body.paths) {
        const remotePath = safePath(p);
        try {
          await fileOps.remove(sftp, remotePath, { recursive: req.body.recursive });
          results.push({ path: remotePath, ok: true });
          await logSafe({
            userId: req.user.id,
            serverId: serverIdOf(req),
            operation: 'DELETE',
            path: remotePath,
            success: true,
          });
        } catch (err) {
          results.push({
            path: remotePath,
            ok: false,
            error: err.message ?? 'Delete failed',
          });
          await logSafe({
            userId: req.user.id,
            serverId: serverIdOf(req),
            operation: 'DELETE',
            path: remotePath,
            success: false,
            errorCode: err.code ?? 'DELETE_FAILED',
          });
        }
      }
    });
    res.json({ ok: true, data: { results } });
  } catch (err) {
    next(err);
  }
}

export async function unzip(req, res, next) {
  try {
    const remotePath = safePath(req.body.path);
    const target = await withSftp(req.user.id, serverIdOf(req), ({ conn }) =>
      shellOps.unzipInPlace(conn, remotePath),
    );
    await logSafe({
      userId: req.user.id,
      serverId: serverIdOf(req),
      operation: 'UNZIP',
      path: remotePath,
      success: true,
    });
    res.json({ ok: true, data: { path: target } });
  } catch (err) {
    await logSafe({
      userId: req.user.id,
      serverId: serverIdOf(req),
      operation: 'UNZIP',
      path: req.body?.path ?? '',
      success: false,
      errorCode: err.code ?? 'UNZIP_FAILED',
    });
    next(err);
  }
}

export async function folderSize(req, res, next) {
  try {
    const dir = safePath(req.query.path);
    const id = serverIdOf(req);
    const cached = folderSizeCache.getCachedSize(id, dir);
    if (cached != null) {
      return res.json({ ok: true, data: { path: dir, bytes: cached, cached: true } });
    }
    const bytes = await withSftp(req.user.id, id, ({ conn }) => shellOps.folderSize(conn, dir));
    folderSizeCache.setCachedSize(id, dir, bytes);
    res.json({ ok: true, data: { path: dir, bytes, cached: false } });
  } catch (err) {
    next(err);
  }
}

export async function resolveSymlink(req, res, next) {
  try {
    const remotePath = safePath(req.query.path);
    const data = await withSftp(req.user.id, serverIdOf(req), async ({ sftp }) => {
      const attrs = await fileOps.statPath(sftp, remotePath);
      return { path: remotePath, size: attrs.size, modeOctal: attrs.mode };
    });
    res.json({ ok: true, data });
  } catch (err) {
    next(mapSftpError(err));
  }
}
