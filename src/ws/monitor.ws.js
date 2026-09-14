import { once } from '../utils/once.js';
import { metricsCoordinator } from '../services/metrics/metricsCoordinator.js';

function sendJson(ws, obj) {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

export function bindMonitorSocket(ws, coordinator = metricsCoordinator) {
  const cleanup = once(() => {
    coordinator.removeSocket(ws);
  });

  ws.on('message', (data) => {
    let msg;
    try {
      msg = JSON.parse(typeof data === 'string' ? data : data.toString());
    } catch {
      return;
    }

    if (msg.type === 'monitor:subscribe') {
      if (msg.serverId !== ws.serverId) {
        sendJson(ws, {
          type: 'monitor:error',
          code: 'FORBIDDEN',
          message: 'You can only monitor this server.',
        });
        return;
      }
      coordinator.subscribe(ws.serverId, ws.userId, ws).catch((err) => {
        sendJson(ws, {
          type: 'monitor:status',
          serverId: ws.serverId,
          state: 'unreachable',
          message: err.message ?? 'Could not start monitoring.',
        });
      });
      return;
    }

    if (msg.type === 'monitor:unsubscribe') {
      coordinator.unsubscribe(ws.serverId, ws);
    }
  });

  ws.on('close', cleanup);
  ws.on('error', cleanup);
}
