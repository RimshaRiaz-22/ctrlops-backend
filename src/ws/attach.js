import { WebSocketServer } from 'ws';
import { consumeTicket } from '../services/terminalTicket.service.js';
import { openTerminalSession } from '../services/terminalSession.service.js';
import { closeAllTerminalSessions } from '../services/terminalSession.service.js';
import { originAllowed } from './origin.js';
import { bindMonitorSocket } from './monitor.ws.js';

function reject(socket, status, reason) {
  socket.write(`HTTP/1.1 ${status} ${reason}\r\n\r\n`);
  socket.destroy();
}

export function attachWs(server) {
  const terminalWss = new WebSocketServer({
    noServer: true,
    perMessageDeflate: false,
    skipUTF8Validation: true,
  });
  const monitorWss = new WebSocketServer({
    noServer: true,
    perMessageDeflate: false,
  });

  server.on('upgrade', (req, socket, head) => {
    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch {
      reject(socket, 400, 'Bad Request');
      return;
    }

    if (!originAllowed(req.headers.origin)) {
      reject(socket, 403, 'Forbidden');
      return;
    }

    const ticket = url.searchParams.get('ticket');

    if (url.pathname === '/ws/terminal') {
      const entry = consumeTicket(ticket, 'terminal');
      if (!entry) {
        reject(socket, 401, 'Unauthorized');
        return;
      }
      terminalWss.handleUpgrade(req, socket, head, (ws) => {
        ws.userId = entry.userId;
        ws.serverId = entry.serverId;
        terminalWss.emit('connection', ws, req);
      });
      return;
    }

    if (url.pathname === '/ws/monitor') {
      const entry = consumeTicket(ticket, 'monitor');
      if (!entry) {
        reject(socket, 401, 'Unauthorized');
        return;
      }
      monitorWss.handleUpgrade(req, socket, head, (ws) => {
        ws.userId = entry.userId;
        ws.serverId = entry.serverId;
        monitorWss.emit('connection', ws, req);
      });
      return;
    }

    reject(socket, 404, 'Not Found');
  });

  terminalWss.on('connection', (ws) => {
    openTerminalSession(ws).catch(() => {
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    });
  });

  monitorWss.on('connection', (ws) => {
    bindMonitorSocket(ws);
  });

  return { terminalWss, monitorWss };
}

/** @deprecated Use attachWs — kept so older tests can import either name. */
export function attachTerminalWs(server) {
  return attachWs(server).terminalWss;
}

let shutdownBound = false;
export function bindTerminalShutdown(httpServer) {
  if (shutdownBound) return;
  shutdownBound = true;

  let stopping = false;
  const onStop = () => {
    if (stopping) return;
    stopping = true;
    closeAllTerminalSessions();
    if (!httpServer) {
      process.exit(0);
      return;
    }
    httpServer.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1500).unref();
  };

  process.on('SIGTERM', onStop);
  process.on('SIGINT', onStop);
  process.on('SIGUSR2', onStop);
}
