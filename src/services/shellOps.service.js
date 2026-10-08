import { AppError } from '../middleware/errorHandler.js';
import { shellQuote } from '../utils/shellQuote.js';
import path from 'path';

function execCommand(conn, cmd) {
  return new Promise((resolve, reject) => {
    conn.exec(cmd, (err, stream) => {
      if (err) return reject(err);
      const chunks = [];
      let stderr = '';
      stream.on('data', (d) => chunks.push(d));
      stream.stderr?.on('data', (d) => {
        stderr += d.toString();
      });
      stream.on('error', reject);
      stream.on('close', (code) => {
        const stdout = Buffer.concat(chunks.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(c))));
        resolve({ code: code ?? 0, stdout, stderr });
      });
    });
  });
}

async function hasBinary(conn, name) {
  const { stdout } = await execCommand(conn, `command -v ${shellQuote(name)}`);
  return stdout.toString().trim().length > 0;
}

export async function folderSize(conn, dirPath) {
  const { stdout, code } = await execCommand(
    conn,
    `du -sb ${shellQuote(dirPath)} 2>/dev/null | cut -f1`,
  );
  const text = stdout.toString().trim();
  const bytes = Number.parseInt(text, 10);
  if (!Number.isFinite(bytes) || (code && code !== 0 && !text)) {
    throw new AppError('FOLDER_SIZE_FAILED', 500, 'Could not calculate folder size.');
  }
  return bytes;
}

export async function unzipInPlace(conn, remotePath) {
  if (!(await hasBinary(conn, 'unzip'))) {
    throw new AppError(
      'MISSING_DEPENDENCY',
      424,
      'unzip is not installed on the server. Install the unzip package.',
    );
  }
  const target = remotePath.replace(/\.zip$/i, '');
  let result;
  try {
    result = await execCommand(
      conn,
      `unzip -o ${shellQuote(remotePath)} -d ${shellQuote(target)}`,
    );
  } catch (err) {
    throw new AppError(
      'UNZIP_FAILED',
      500,
      'Could not expand the archive.',
      err.message?.slice(0, 200),
    );
  }
  const { code, stderr } = result;
  if (code && code !== 0) {
    throw new AppError(
      'UNZIP_FAILED',
      500,
      'Could not expand the archive.',
      stderr.slice(0, 200) || undefined,
    );
  }
  return target;
}

export async function assertZipInstalled(conn) {
  if (!(await hasBinary(conn, 'zip'))) {
    throw new AppError(
      'MISSING_DEPENDENCY',
      424,
      'zip is not installed on the server. Install the zip package.',
    );
  }
}

export async function zipDownload(conn, directory, files, res) {
  await assertZipInstalled(conn);
  const quoted = files.map(shellQuote).join(' ');
  const cmd = `cd ${shellQuote(directory)} && zip -r - ${quoted}`;
  return new Promise((resolve, reject) => {
    conn.exec(cmd, (err, stream) => {
      if (err) return reject(err);
      stream.on('error', reject);
      stream.stderr?.on('data', () => {});
      stream.on('close', () => resolve());
      stream.pipe(res);
    });
  });
}

export function zipFilename(directory) {
  const base = path.posix.basename(directory) || 'download';
  return `${base}.zip`;
}
