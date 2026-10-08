import { EventEmitter } from 'events';
import { Duplex, PassThrough, Readable } from 'stream';
import path from 'path';
import { S_IFDIR, S_IFREG, S_IFLNK } from '../utils/posixMode.js';
import { formatMode } from '../utils/posixMode.js';
import { buildMockMetricsOutput } from './metrics/mockMetricsOutput.js';

function nowSec() {
  return 1_700_000_000;
}

function sftpError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function parseQuotedArgs(cmd) {
  const args = [];
  let current = '';
  let inSingle = false;
  for (let i = 0; i < cmd.length; i += 1) {
    const ch = cmd[i];
    if (inSingle) {
      if (ch === "'" && cmd.slice(i, i + 4) === `'\\''`) {
        current += "'";
        i += 3;
      } else if (ch === "'") {
        inSingle = false;
      } else {
        current += ch;
      }
    } else if (ch === "'") {
      inSingle = true;
    } else if (/\s/.test(ch)) {
      if (current) {
        args.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }
  if (current) args.push(current);
  return args;
}

function makeNode({ type, mode, content = Buffer.alloc(0), target = null, uid = 1000, gid = 1000 }) {
  const typeBit = type === 'directory' ? S_IFDIR : type === 'symlink' ? S_IFLNK : S_IFREG;
  return {
    type,
    mode: typeBit | (mode & 0o777),
    content: Buffer.from(content),
    target,
    uid,
    gid,
    atime: nowSec(),
    mtime: nowSec(),
  };
}

function seedTree() {
  const nodes = new Map();
  const mkdir = (p, mode = 0o755, uid = 1000) => {
    nodes.set(p, makeNode({ type: 'directory', mode, uid, gid: uid }));
  };
  const write = (p, content, mode = 0o644, uid = 1000) => {
    nodes.set(p, makeNode({ type: 'file', mode, content: Buffer.from(content), uid, gid: uid }));
  };

  mkdir('/');
  mkdir('/home');
  mkdir('/home/ubuntu');
  mkdir('/home/ubuntu/backups');
  mkdir('/home/ubuntu/www');
  mkdir('/home/ubuntu/logs');
  mkdir('/tmp', 0o1777);
  mkdir('/root', 0o700, 0);
  mkdir('/root/secret', 0o700, 0);

  write('/home/ubuntu/nginx.conf', 'server {\n  listen 80;\n}\n');
  write('/home/ubuntu/.env', 'SECRET=abc123\n', 0o600);
  write('/home/ubuntu/deploy.sh', '#!/bin/bash\necho hi\n', 0o755);
  write('/home/ubuntu/binary.dat', Buffer.from([0x00, 0x01, 0x02, 0xff, 0x00]));
  write('/home/ubuntu/file with spaces.txt', 'spaces\n');
  write('/home/ubuntu/файл.txt', 'unicode\n');
  write('/home/ubuntu/test$(whoami).txt', 'meta\n');
  write('/root/secret/shadow', 'root:*:0:0\n', 0o600, 0);

  return nodes;
}

function longname(name, node) {
  const perms = formatMode(node.mode);
  const owner = node.uid === 0 ? 'root' : 'ubuntu';
  const size = node.type === 'file' ? node.content.length : 4096;
  return `${perms} 1 ${owner} ${owner} ${size} Jan 1 00:00 ${name}`;
}

function ownerName(uid) {
  return uid === 0 ? 'root' : 'ubuntu';
}

function createMockPty({ username, cols, rows }) {
  let cwd = `/home/${username}`;
  let lineBuf = '';
  let cols_ = cols;
  let rows_ = rows;
  let closed = false;

  const stream = new Duplex({
    write(chunk, _enc, cb) {
      if (closed) {
        cb();
        return;
      }
      const text = chunk.toString('utf8');
      for (const ch of text) {
        if (ch === '\r' || ch === '\n') {
          const cmd = lineBuf.trim();
          lineBuf = '';
          stream.push('\r\n');
          handleCmd(cmd);
          if (!closed) stream.push(`${username}@mock:${cwd}$ `);
        } else if (ch === '\x03') {
          lineBuf = '';
          stream.push('^C\r\n');
          stream.push(`${username}@mock:${cwd}$ `);
        } else if (ch === '\x04') {
          stream.push('logout\r\n');
          closeStream(0);
        } else if (ch === '\x7f' || ch === '\b') {
          if (lineBuf.length) {
            lineBuf = lineBuf.slice(0, -1);
            stream.push('\b \b');
          }
        } else if (ch !== '\x00') {
          lineBuf += ch;
          stream.push(ch);
        }
      }
      cb();
    },
    read() {},
  });

  function closeStream(code) {
    if (closed) return;
    closed = true;
    stream.push(null);
    stream.emit('exit', code);
    stream.emit('close');
  }

  function handleCmd(cmd) {
    if (!cmd) return;
    if (cmd === 'whoami') {
      stream.push(`${username}\r\n`);
      return;
    }
    if (cmd === 'pwd') {
      stream.push(`${cwd}\r\n`);
      return;
    }
    if (cmd === 'exit') {
      stream.push('logout\r\n');
      closeStream(0);
      return;
    }
    if (cmd.startsWith('echo ')) {
      const arg = cmd.slice(5).trim();
      if (arg === '$COLUMNS') stream.push(`${cols_}\r\n`);
      else if (arg === '$LINES') stream.push(`${rows_}\r\n`);
      else stream.push(`${arg.replace(/^['"]|['"]$/g, '')}\r\n`);
      return;
    }
    if (cmd.startsWith('cd ')) {
      const next = cmd.slice(3).trim() || `/home/${username}`;
      cwd = next.startsWith('/') ? next : `${cwd}/${next}`;
      return;
    }
    if (cmd === 'yes') {
      for (let i = 0; i < 200; i += 1) stream.push('y\r\n');
      return;
    }
    stream.push(`mock: ${cmd}: command not found\r\n`);
  }

  stream.setWindow = (r, c) => {
    rows_ = r;
    cols_ = c;
  };
  stream.stderr = new PassThrough();

  queueMicrotask(() => {
    if (!closed) stream.push(`${username}@mock:${cwd}$ `);
  });

  return stream;
}

export function createMockSshSession({ username = 'ubuntu' } = {}) {
  const nodes = seedTree();
  const emitter = new EventEmitter();
  let closed = false;

  function exists(p) {
    return nodes.has(p);
  }

  function get(p) {
    const node = nodes.get(p);
    if (!node) throw sftpError(2, 'No such file');
    if (p.startsWith('/root') && username !== 'root') {
      throw sftpError(3, 'Permission denied');
    }
    return node;
  }

  function parentDir(p) {
    if (p === '/') return null;
    return path.posix.dirname(p);
  }

  const sftp = {
    readdir(dirPath, cb) {
      try {
        const node = get(dirPath);
        if (node.type !== 'directory') throw sftpError(4, 'Not a directory');
        const entries = [];
        for (const [p, n] of nodes) {
          if (p === dirPath) continue;
          if (path.posix.dirname(p) === dirPath) {
            const filename = path.posix.basename(p);
            entries.push({
              filename,
              longname: longname(filename, n),
              attrs: attrsOf(n),
            });
          }
        }
        cb(null, entries);
      } catch (err) {
        cb(err);
      }
    },
    stat(p, cb) {
      try {
        const node = get(p);
        cb(null, attrsOf(node));
      } catch (err) {
        cb(err);
      }
    },
    lstat(p, cb) {
      this.stat(p, cb);
    },
    realpath(p, cb) {
      try {
        if (p === '.' || p === '') {
          cb(null, username === 'root' ? '/root' : '/home/ubuntu');
          return;
        }
        const normalized = path.posix.normalize(p);
        get(normalized);
        cb(null, normalized);
      } catch (err) {
        cb(err);
      }
    },
    mkdir(p, cb) {
      try {
        if (exists(p)) throw sftpError(4, 'Failure: file exists');
        const parent = parentDir(p);
        get(parent);
        nodes.set(p, makeNode({ type: 'directory', mode: 0o755 }));
        cb(null);
      } catch (err) {
        cb(err);
      }
    },
    rmdir(p, cb) {
      try {
        const node = get(p);
        if (node.type !== 'directory') throw sftpError(4, 'Failure');
        for (const key of nodes.keys()) {
          if (key !== p && (key.startsWith(`${p}/`) || (p === '/' && key !== '/'))) {
            if (p !== '/' && key.startsWith(`${p}/`)) {
              throw sftpError(4, 'Failure: directory not empty');
            }
          }
        }
        const hasChild = [...nodes.keys()].some((k) => k !== p && k.startsWith(`${p}/`));
        if (hasChild) throw sftpError(4, 'Failure: directory not empty');
        nodes.delete(p);
        cb(null);
      } catch (err) {
        cb(err);
      }
    },
    unlink(p, cb) {
      try {
        const node = get(p);
        if (node.type === 'directory') throw sftpError(4, 'Failure');
        nodes.delete(p);
        cb(null);
      } catch (err) {
        cb(err);
      }
    },
    rename(from, to, cb) {
      try {
        const node = get(from);
        const dest = nodes.get(to);
        if (dest?.type === 'directory') {
          throw sftpError(4, 'Failure: file exists');
        }
        if (dest) nodes.delete(to);
        get(parentDir(to));
        nodes.set(to, { ...node, mtime: nowSec() });
        nodes.delete(from);
        if (node.type === 'directory') {
          const moved = [];
          for (const [k, v] of nodes) {
            if (k.startsWith(`${from}/`)) {
              moved.push([k.replace(from, to), v]);
              nodes.delete(k);
            }
          }
          for (const [k, v] of moved) nodes.set(k, v);
        }
        cb(null);
      } catch (err) {
        cb(err);
      }
    },
    chmod(p, mode, cb) {
      try {
        const node = get(p);
        const typeBit = node.mode & 0o170000;
        node.mode = typeBit | (mode & 0o777);
        cb(null);
      } catch (err) {
        cb(err);
      }
    },
    createReadStream(p) {
      const stream = new PassThrough();
      queueMicrotask(() => {
        try {
          const node = get(p);
          if (node.type === 'directory') throw sftpError(4, 'Failure');
          stream.end(Buffer.from(node.content));
        } catch (err) {
          stream.destroy(err);
        }
      });
      return stream;
    },
    createWriteStream(p) {
      const chunks = [];
      const stream = new PassThrough();
      stream.on('data', (c) => chunks.push(c));
      stream.on('end', () => {
        try {
          const buf = Buffer.concat(chunks);
          const parent = parentDir(p);
          get(parent);
          const existing = nodes.get(p);
          nodes.set(
            p,
            makeNode({
              type: 'file',
              mode: existing ? existing.mode & 0o777 : 0o644,
              content: buf,
            }),
          );
          stream.emit('close');
        } catch (err) {
          stream.destroy(err);
        }
      });
      return stream;
    },
  };

  function attrsOf(node) {
    return {
      mode: node.mode,
      uid: node.uid,
      gid: node.gid,
      size: node.type === 'directory' ? 4096 : node.content.length,
      atime: node.atime,
      mtime: node.mtime,
    };
  }

  function duBytes(dirPath) {
    let total = 0;
    for (const [p, n] of nodes) {
      if (p === dirPath || p.startsWith(`${dirPath}/`) || (dirPath === '/' && p !== '/')) {
        if (n.type === 'file') total += n.content.length;
      }
    }
    return total;
  }

  function extractZip(zipPath, dest) {
    const node = get(zipPath);
    const text = node.content.toString('utf8');
    if (!nodes.has(dest)) {
      nodes.set(dest, makeNode({ type: 'directory', mode: 0o755 }));
    }
    const marker = 'MOCKZIP:';
    if (text.startsWith(marker)) {
      const files = JSON.parse(text.slice(marker.length));
      for (const [rel, body] of Object.entries(files)) {
        const full = path.posix.join(dest, rel);
        const parent = parentDir(full);
        if (!nodes.has(parent)) {
          nodes.set(parent, makeNode({ type: 'directory', mode: 0o755 }));
        }
        nodes.set(
          full,
          makeNode({
            type: 'file',
            mode: 0o644,
            content: Buffer.from(body, 'base64'),
          }),
        );
      }
    } else {
      const name = path.posix.basename(zipPath).replace(/\.zip$/i, '') + '-extracted.txt';
      nodes.set(
        path.posix.join(dest, name),
        makeNode({ type: 'file', mode: 0o644, content: Buffer.from('extracted\n') }),
      );
    }
  }

  function makeZip(dir, files) {
    const payload = {};
    for (const name of files) {
      const p = path.posix.join(dir, name);
      const node = get(p);
      if (node.type === 'file') payload[name] = node.content.toString('base64');
      else payload[name] = '';
    }
    return Buffer.from(`MOCKZIP:${JSON.stringify(payload)}`);
  }

  const conn = {
    on(ev, fn) {
      emitter.on(ev, fn);
      return conn;
    },
    end() {
      if (closed) return;
      closed = true;
      emitter.emit('close');
    },
    shell(opts, cb) {
      if (closed) {
        return cb(sftpError(7, 'Connection lost'));
      }
      const stream = createMockPty({
        username,
        cols: opts?.cols ?? 80,
        rows: opts?.rows ?? 24,
      });
      queueMicrotask(() => cb(null, stream));
    },
    exec(cmd, cb) {
      if (closed) {
        return cb(sftpError(7, 'Connection lost'));
      }
      const stream = new PassThrough();
      stream.stderr = new PassThrough();
      const args = parseQuotedArgs(cmd);
      queueMicrotask(() => {
        try {
          const cmdStr = String(cmd);
          if (cmdStr.includes('===CPU===')) {
            stream.end(buildMockMetricsOutput());
            return;
          }
          if (cmdStr.includes('===OS===') && cmdStr.includes('===SUDO===')) {
            stream.end(
              [
                '===OS===',
                'NAME="Ubuntu"',
                'ID=ubuntu',
                'VERSION_ID="22.04"',
                '===SUDO===',
                'EXIT:0',
                '===USER===',
                '1000',
                '===DONE===',
                '',
              ].join('\n'),
            );
            return;
          }
          if (cmdStr.includes('===APP:')) {
            // Server applicability succeeds on mock; Web/Docker/DB absent → SKIP (US-A05)
            const ids = [...cmdStr.matchAll(/===APP:([^=]+)===/g)].map((m) => m[1]);
            let out = '';
            for (const id of ids) {
              const applicable = !/^(docker-|web-|db-)/.test(id);
              out += `===APP:${id}===\n${applicable ? 'yes' : 'no'}\n`;
            }
            out += '===DONE===\n';
            stream.end(out);
            return;
          }
          if (cmdStr.includes('===CHECK:')) {
            const fixtures = {
              'ssh-root-login': 'PermitRootLogin yes',
              'ssh-password-auth': 'PasswordAuthentication yes',
              'ssh-permit-empty-passwords': 'PermitEmptyPasswords no',
              'ssh-max-auth-tries': 'MaxAuthTries 6',
              'ssh-client-alive': 'ClientAliveInterval 0\nClientAliveCountMax 3',
              'ssh-x11-forwarding': 'X11Forwarding yes',
              'ssh-protocol': '',
              'app-tls-cert-expiry': 'DONE',
              'app-node-version': 'v20.11.0',
              'app-python-version': 'Python 3.11.6',
              'app-db-listening-localhost': 'NONE',
              'app-world-readable-env': '0',
              'fs-world-writable-files': '0',
              'fs-world-writable-dirs': '0',
              'fs-suid-binaries': '25',
              'fs-shadow-perms': '640 root:shadow',
              'fs-passwd-perms': '644',
              'fs-home-dot-ssh': '/home/ubuntu/.ssh 700',
              'fs-tmp-sticky': '1777',
              'fw-enabled': 'Status: active',
              'fw-ssh-open': 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*',
              'fw-risky-ports': 'NONE',
              'fw-ip-forward': '0',
              'fw-docker-iptables': 'NO_DOCKER_USER',
              'fw-syn-cookies': '1',
              'user-empty-password-hashes': '',
              'user-duplicate-uids': '',
              'user-uid0-accounts': 'root',
              'user-sudo-group': 'sudo:x:27:ubuntu\n---\n%sudo ALL=(ALL:ALL) ALL',
              'user-password-aging': 'PASS_MAX_DAYS\t90',
              'user-nopasswd-sudo': 'NONE',
              'sysctl-ip-forward': '0',
              'sysctl-accept-source-route': '0\n0',
              'sysctl-aslr': '2',
              'sysctl-kptr-restrict': '1',
              'sysctl-core-dumps': '0',
              'upd-pending-security': '0',
              'upd-unattended-upgrades': 'APT::Periodic::Unattended-Upgrade "1";',
              'upd-reboot-required': 'NO',
              'upd-package-manager-present': '/usr/bin/apt-get',
            };
            const ids = [...cmdStr.matchAll(/===CHECK:([^=]+)===/g)].map((m) => m[1]);
            let out = '';
            for (const id of ids) {
              out += `===CHECK:${id}===\n${fixtures[id] ?? ''}\n===EXIT:0===\n`;
            }
            out += '===DONE===\n';
            stream.end(out);
            return;
          }
          if (args[0] === 'command' && args[1] === '-v') {
            const bin = args[2];
            if (bin === 'zip' || bin === 'unzip') {
              stream.end(`/usr/bin/${bin}\n`);
            } else {
              stream.end('');
            }
            return;
          }
          if (args[0] === 'du') {
            const dir = args.find((a) => a.startsWith('/')) ?? args[args.length - 1];
            const bytes = duBytes(dir);
            stream.end(`${bytes}\n`);
            return;
          }
          if (args[0] === 'cd') {
            const dir = args[1];
            const zipIdx = args.indexOf('zip');
            const files = args.slice(zipIdx + 3);
            const buf = makeZip(dir, files);
            stream.end(buf);
            return;
          }
          if (args[0] === 'unzip') {
            const zipPath = args[2];
            const destIdx = args.indexOf('-d');
            const dest = args[destIdx + 1];
            extractZip(zipPath, dest);
            stream.end('inflating\n');
            return;
          }
          stream.end('');
        } catch (err) {
          stream.emit('error', err);
          stream.end();
        }
      });
      cb(null, stream);
    },
  };

  sftp._nodes = nodes;
  sftp._ownerName = ownerName;

  return { conn, sftp, nodes };
}

export { ownerName, parseQuotedArgs };
