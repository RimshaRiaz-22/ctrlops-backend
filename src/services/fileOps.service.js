import path from 'path';
import { AppError } from '../middleware/errorHandler.js';
import { promisifySftp } from './sshPool.service.js';
import { mapSftpError } from './fileError.service.js';
import {
  entryType,
  formatMode,
  modeOctal,
  isDirMode,
} from '../utils/posixMode.js';
import { buildBreadcrumbs, parentPath } from '../utils/safePath.js';
import { isEditableFile, isBinaryBuffer, languageFromPath } from '../utils/languageFromPath.js';

function ownerFromLongname(longname, uid) {
  const parts = (longname ?? '').trim().split(/\s+/);
  if (parts.length >= 4 && Number.isNaN(Number(parts[2]))) {
    return { owner: parts[2], group: parts[3] };
  }
  return {
    owner: uid === 0 ? 'root' : String(uid ?? ''),
    group: String(uid ?? ''),
  };
}

function toEntry(item) {
  const mode = item.attrs?.mode ?? 0;
  const type = entryType(mode);
  const { owner, group } = ownerFromLongname(item.longname, item.attrs?.uid);
  const ext = item.filename.includes('.')
    ? item.filename.split('.').pop()
    : null;
  const size = item.attrs?.size ?? 0;
  return {
    name: item.filename,
    type,
    size,
    mode: formatMode(mode),
    modeOctal: modeOctal(mode),
    owner,
    group,
    modifiedAt: item.attrs?.mtime
      ? new Date(item.attrs.mtime * 1000).toISOString()
      : null,
    isHidden: item.filename.startsWith('.'),
    isSymlink: type === 'symlink',
    extension: type === 'file' && ext ? ext : null,
    isEditable: isEditableFile({ name: item.filename, type, size }),
  };
}

export async function listDirectory(sftp, dirPath) {
  try {
    const stat = promisifySftp(sftp, 'stat');
    const readdir = promisifySftp(sftp, 'readdir');
    const attrs = await stat(dirPath);
    if (!isDirMode(attrs.mode)) {
      throw new AppError('NOT_A_DIRECTORY', 400, "That's a file, not a folder.");
    }
    const raw = await readdir(dirPath);
    const entries = raw
      .filter((e) => e.filename !== '.' && e.filename !== '..')
      .map(toEntry)
      .sort((a, b) => {
        if (a.type === 'directory' && b.type !== 'directory') return -1;
        if (a.type !== 'directory' && b.type === 'directory') return 1;
        return a.name.localeCompare(b.name);
      });

    return {
      path: dirPath,
      parent: parentPath(dirPath),
      breadcrumbs: buildBreadcrumbs(dirPath),
      entries,
      totalItems: entries.length,
    };
  } catch (err) {
    throw mapSftpError(err);
  }
}

export async function resolveDefaultPath(sftp) {
  try {
    const realpath = promisifySftp(sftp, 'realpath');
    return await realpath('.');
  } catch {
    return '/';
  }
}

export async function statPath(sftp, remotePath) {
  try {
    return await promisifySftp(sftp, 'stat')(remotePath);
  } catch (err) {
    throw mapSftpError(err);
  }
}

export async function mkdir(sftp, remotePath) {
  try {
    await promisifySftp(sftp, 'mkdir')(remotePath);
  } catch (err) {
    if (err?.code === 4 || /exists/i.test(err?.message ?? '')) {
      throw new AppError('CONFLICT', 409, 'An item with that name already exists.');
    }
    throw mapSftpError(err);
  }
}

export async function mkdirp(sftp, remotePath) {
  const parts = remotePath.split('/').filter(Boolean);
  let acc = '';
  for (const part of parts) {
    acc += `/${part}`;
    try {
      const attrs = await promisifySftp(sftp, 'stat')(acc);
      if (!isDirMode(attrs.mode)) {
        throw new AppError('NOT_A_DIRECTORY', 400, "That's a file, not a folder.");
      }
    } catch (err) {
      if (err instanceof AppError) throw err;
      if (err?.code === 2 || err?.code === 'ENOENT') {
        await mkdir(sftp, acc);
      } else if (err?.statusCode) {
        throw err;
      } else {
        try {
          await mkdir(sftp, acc);
        } catch (mkdirErr) {
          if (!(mkdirErr instanceof AppError && mkdirErr.code === 'CONFLICT')) {
            throw mkdirErr;
          }
        }
      }
    }
  }
}

export async function rename(sftp, from, to) {
  try {
    try {
      await promisifySftp(sftp, 'stat')(to);
      throw new AppError('CONFLICT', 409, 'An item with that name already exists.');
    } catch (err) {
      if (err instanceof AppError && err.code === 'CONFLICT') throw err;
      if (!(err?.code === 2 || err?.code === 'ENOENT' || err?.statusCode === 404)) {
        if (err instanceof AppError) throw err;
      }
    }
    await promisifySftp(sftp, 'rename')(from, to);
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw mapSftpError(err);
  }
}

export async function remove(sftp, remotePath, { recursive = false } = {}) {
  try {
    const attrs = await promisifySftp(sftp, 'stat')(remotePath);
    if (isDirMode(attrs.mode)) {
      const children = await promisifySftp(sftp, 'readdir')(remotePath);
      const real = children.filter((c) => c.filename !== '.' && c.filename !== '..');
      if (real.length > 0 && !recursive) {
        throw new AppError(
          'DIRECTORY_NOT_EMPTY',
          409,
          'This folder is not empty. Confirm recursive delete.',
        );
      }
      for (const child of real) {
        await remove(sftp, path.posix.join(remotePath, child.filename), { recursive: true });
      }
      await promisifySftp(sftp, 'rmdir')(remotePath);
      return;
    }
    await promisifySftp(sftp, 'unlink')(remotePath);
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw mapSftpError(err);
  }
}

export function createWriteStream(sftp, remotePath) {
  return sftp.createWriteStream(remotePath, { highWaterMark: 1024 * 1024 });
}

export function createReadStream(sftp, remotePath) {
  return sftp.createReadStream(remotePath);
}

export async function unlink(sftp, remotePath) {
  try {
    await promisifySftp(sftp, 'unlink')(remotePath);
  } catch {
    /* ignore missing partials */
  }
}

export async function chmod(sftp, remotePath, mode) {
  await promisifySftp(sftp, 'chmod')(remotePath, mode);
}

export async function readFileLimited(sftp, remotePath, { maxBytes = 5 * 1024 * 1024 } = {}) {
  const attrs = await statPath(sftp, remotePath);
  if (isDirMode(attrs.mode)) {
    throw new AppError('NOT_A_FILE', 400, "That's a folder, not a file.");
  }
  if (attrs.size > maxBytes) {
    throw new AppError(
      'FILE_TOO_LARGE',
      413,
      'This file is over 5 MB. Use download instead of the editor.',
    );
  }

  const head = await readBytes(sftp, remotePath, 8192);
  if (isBinaryBuffer(head)) {
    throw new AppError(
      'BINARY_FILE',
      415,
      'This looks like a binary file and cannot be opened as text.',
    );
  }

  const content = await readAll(sftp, remotePath);
  return {
    path: remotePath,
    content: content.toString('utf8'),
    size: attrs.size,
    modeOctal: modeOctal(attrs.mode),
    mode: attrs.mode,
    modifiedAt: new Date(attrs.mtime * 1000).toISOString(),
    language: languageFromPath(remotePath),
    encoding: 'utf-8',
  };
}

function readBytes(sftp, remotePath, n) {
  return new Promise((resolve, reject) => {
    const stream = sftp.createReadStream(remotePath, { start: 0, end: n - 1 });
    const chunks = [];
    stream.on('data', (c) => chunks.push(c));
    stream.on('error', reject);
    stream.on('end', () => resolve(Buffer.concat(chunks)));
  });
}

function readAll(sftp, remotePath) {
  return new Promise((resolve, reject) => {
    const stream = sftp.createReadStream(remotePath);
    const chunks = [];
    stream.on('data', (c) => chunks.push(c));
    stream.on('error', reject);
    stream.on('end', () => resolve(Buffer.concat(chunks)));
  });
}

export async function atomicWrite(sftp, remotePath, content, { expectedModifiedAt, force = false } = {}) {
  const attrs = await statPath(sftp, remotePath);
  const currentMs = attrs.mtime * 1000;
  if (!force && expectedModifiedAt) {
    const expectedMs = Date.parse(expectedModifiedAt);
    const currentSec = Math.floor(currentMs / 1000);
    const expectedSec = Math.floor(expectedMs / 1000);
    if (!Number.isFinite(expectedMs) || expectedSec !== currentSec) {
      throw new AppError(
        'FILE_MODIFIED_EXTERNALLY',
        409,
        'This file changed on the server since you opened it.',
      );
    }
  }

  const tmp = `${remotePath}.ctrlops.tmp`;
  try {
    await writeBuffer(sftp, tmp, Buffer.from(content, 'utf8'));
    await chmod(sftp, tmp, attrs.mode & 0o777);
    await promisifySftp(sftp, 'rename')(tmp, remotePath);
  } catch (err) {
    await unlink(sftp, tmp);
    if (err instanceof AppError) throw err;
    throw mapSftpError(err);
  }

  return {
    path: remotePath,
    modeOctal: modeOctal(attrs.mode),
    modifiedAt: new Date().toISOString(),
  };
}

function writeBuffer(sftp, remotePath, buf) {
  return new Promise((resolve, reject) => {
    const stream = sftp.createWriteStream(remotePath);
    stream.on('error', reject);
    stream.on('close', resolve);
    stream.end(buf);
  });
}

export { toEntry };
