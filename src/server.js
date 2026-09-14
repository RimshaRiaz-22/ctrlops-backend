import http from 'http';
import app from './app.js';
import { env } from './config/env.js';
import { checkConnection } from './config/db.js';
import { logger } from './utils/logger.js';
import { attachWs, bindTerminalShutdown } from './ws/attach.js';
import * as auditRunRepo from './repositories/auditRun.repository.js';

async function start() {
  try {
    await checkConnection();
    logger.info('Database connected');

    const reaped = await auditRunRepo.failAllRunning();
    if (reaped > 0) {
      logger.warn(`Marked ${reaped} stale RUNNING audit run(s) as FAILED`);
    }

    const server = http.createServer(app);
    attachWs(server);
    bindTerminalShutdown(server);

    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        logger.error(`Port ${env.PORT} is already in use. Stop the other process and retry.`);
        process.exit(1);
      }
      logger.error('HTTP server error:', err);
      process.exit(1);
    });

    server.listen(env.PORT, () => {
      logger.info(`API listening on http://localhost:${env.PORT}`);
    });
  } catch (err) {
    logger.error('Failed to start server:', err);
    process.exit(1);
  }
}

start();
