import { METRICS_COMMAND, METRICS_COMMAND_BURST } from './metricsCommand.js';
import { parseMetrics } from './metricsParser.js';

const TIMEOUT_MS = 8000;

export function collectSample(conn, { burst = false } = {}) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(Object.assign(new Error('METRICS_TIMEOUT'), { code: 'METRICS_TIMEOUT' }));
    }, TIMEOUT_MS);

    const cmd = burst ? METRICS_COMMAND_BURST : METRICS_COMMAND;

    conn.exec(cmd, (err, stream) => {
      if (err) {
        clearTimeout(timer);
        return reject(err);
      }

      let out = '';
      stream.on('data', (d) => {
        out += d.toString();
      });
      stream.stderr?.on('data', () => {});

      stream.on('error', (streamErr) => {
        clearTimeout(timer);
        reject(streamErr);
      });

      stream.on('close', () => {
        clearTimeout(timer);
        try {
          resolve(parseMetrics(out));
        } catch (parseErr) {
          reject(parseErr);
        }
      });
    });
  });
}
