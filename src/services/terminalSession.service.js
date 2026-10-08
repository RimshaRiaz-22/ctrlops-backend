import { randomUUID } from 'crypto';
import { AppError } from '../middleware/errorHandler.js';
import { logger } from '../utils/logger.js';
import { once } from '../utils/once.js';
import { parseControlMessage } from './terminalControl.js';
import { pinSession, unpinSession } from './sshPool.service.js';
import * as registry from './terminalRegistry.js';
import * as serverRepo from '../repositories/server.repository.js';
import { mapSshError } from './sshError.service.js';

const MAX_BUFFERED = 1_000_000;
const RESUME_THRESHOLD = 256_000;
const HEARTBEAT_MS = 30_000;

function sendJson(ws, obj) {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

function sendError(ws, code, message) {
  sendJson(ws, { type: 'error', code, message });
}

function mapConnectError(err) {
  if (err instanceof AppError) {
    if (err.code === 'NOT_FOUND') {
      return { code: 'SERVER_NOT_FOUND', message: 'Server not found.' };
    }
    if (err.code === 'HOST_KEY_MISMATCH') {
      return {
        code: 'HOST_KEY_MISMATCH',
        message: "The server's identity has changed. Verify before reconnecting.",
      };
    }
    return {
      code: 'CONNECTION_FAILED',
      message: "Couldn't reach the server. Check it's online.",
    };
  }
  const mapped = mapSshError(err);
  if (mapped.code === 'HOST_KEY_MISMATCH') {
    return {
      code: 'HOST_KEY_MISMATCH',
      message: "The server's identity has changed. Verify before reconnecting.",
    };
  }
  return {
    code: 'CONNECTION_FAILED',
    message: "Couldn't reach the server. Check it's online.",
  };
}

export async function openTerminalSession(ws) {
  const { userId, serverId } = ws;
  const initialCols = 80;
  const initialRows = 24;

  const owned = await serverRepo.findOwned(serverId, userId);
  if (!owned) {
    sendError(ws, 'SERVER_NOT_FOUND', 'Server not found.');
    ws.close();
    return;
  }

  if (registry.isAtCap(userId, serverId)) {
    sendError(
      ws,
      'SESSION_LIMIT',
      'You have too many terminals open on this server.',
    );
    ws.close();
    return;
  }

  let stream = null;
  const pendingIn = [];
  let pendingResize = { cols: initialCols, rows: initialRows };

  ws.on('message', (data, isBinary) => {
    if (isBinary) {
      if (stream) stream.write(data);
      else pendingIn.push(data);
      return;
    }
    const raw = typeof data === 'string' ? data : data.toString('utf8');
    const msg = parseControlMessage(raw);
    if (!msg.ok) return;
    if (msg.type === 'resize') {
      pendingResize = { cols: msg.cols, rows: msg.rows };
      stream?.setWindow?.(msg.rows, msg.cols, 0, 0);
    } else if (msg.type === 'ping') {
      sendJson(ws, { type: 'pong' });
    }
  });

  let entry;
  try {
    entry = await pinSession(userId, serverId);
  } catch (err) {
    const mapped = mapConnectError(err);
    sendError(ws, mapped.code, mapped.message);
    ws.close();
    return;
  }

  if (ws.readyState !== ws.OPEN) {
    unpinSession(userId, serverId);
    return;
  }

  try {
    entry.conn.setNoDelay?.(true);
  } catch {
    /* mock / already closed */
  }

  const sessionId = randomUUID();

  entry.conn.shell(
    { term: 'xterm-256color', cols: pendingResize.cols, rows: pendingResize.rows },
    (err, pty) => {
      if (err) {
        unpinSession(userId, serverId);
        sendError(ws, 'SHELL_FAILED', 'The server refused to open a shell session.');
        ws.close();
        return;
      }

      if (ws.readyState !== ws.OPEN) {
        try {
          pty.end();
        } catch {
          /* ignore */
        }
        unpinSession(userId, serverId);
        return;
      }

      stream = pty;
      for (const chunk of pendingIn) {
        pty.write(chunk);
      }
      pendingIn.length = 0;
      pty.setWindow?.(pendingResize.rows, pendingResize.cols, 0, 0);

      const drainTimer = setInterval(() => {
        if (pty.isPaused?.() && ws.bufferedAmount < RESUME_THRESHOLD) {
          pty.resume();
        }
      }, 50);
      drainTimer.unref?.();

      ws.isAlive = true;
      const heartbeat = setInterval(() => {
        if (!ws.isAlive) {
          cleanup();
          try {
            ws.terminate();
          } catch {
            /* ignore */
          }
          return;
        }
        ws.isAlive = false;
        try {
          ws.ping();
        } catch {
          cleanup();
        }
      }, HEARTBEAT_MS);
      heartbeat.unref?.();

      const cleanup = once(() => {
        clearInterval(drainTimer);
        clearInterval(heartbeat);
        stream = null;
        pty.removeAllListeners();
        try {
          pty.end();
        } catch {
          /* ignore */
        }
        registry.remove(sessionId);
        unpinSession(userId, serverId);
        logger.info({ event: 'terminal.close', sessionId, userId, serverId });
        if (ws.readyState === ws.OPEN) {
          sendJson(ws, { type: 'status', state: 'closed' });
          ws.close();
        }
      });

      registry.add({
        sessionId,
        userId,
        serverId,
        ws,
        stream: pty,
        createdAt: Date.now(),
        cleanup,
      });

      logger.info({ event: 'terminal.open', sessionId, userId, serverId });

      pty.on('data', (chunk) => {
        if (ws.readyState !== ws.OPEN) return;
        if (ws.bufferedAmount > MAX_BUFFERED) pty.pause();
        ws.send(chunk, { binary: true });
      });

      if (pty.stderr?.on) {
        pty.stderr.on('data', (chunk) => {
          if (ws.readyState === ws.OPEN) ws.send(chunk, { binary: true });
        });
      }

      pty.on('close', cleanup);
      pty.on('exit', (code) => {
        sendJson(ws, { type: 'exit', code: code ?? 0 });
        cleanup();
      });

      ws.on('pong', () => {
        ws.isAlive = true;
      });

      ws.on('close', cleanup);
      ws.on('error', cleanup);

      sendJson(ws, { type: 'status', state: 'connected' });
    },
  );
}

export function closeAllTerminalSessions() {
  for (const session of registry.listAll()) {
    session.cleanup?.();
  }
}
