import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { env } from './config/env.js';
import { errorHandler } from './middleware/errorHandler.js';
import authRoutes from './routes/auth.routes.js';
import serverRoutes from './routes/server.routes.js';
import preferenceRoutes from './routes/preference.routes.js';
import terminalRoutes from './routes/terminal.routes.js';
import monitorRoutes from './routes/monitor.routes.js';
import scriptRoutes from './routes/script.routes.js';
import auditRoutes, { createServerAuditRouter } from './routes/audit.routes.js';

const app = express();

app.use(helmet());
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (env.NODE_ENV === 'production') {
        return callback(null, origin === env.FRONTEND_URL);
      }
      try {
        const { hostname } = new URL(origin);
        const local = hostname === 'localhost' || hostname === '127.0.0.1';
        return callback(null, local);
      } catch {
        return callback(null, false);
      }
    },
    credentials: true,
    exposedHeaders: ['Content-Disposition', 'Content-Length'],
  }),
);
app.use(
  express.json({
    limit: '32kb',
    type: (req) => {
      if (req.method === 'PUT' && /\/files\/content\/?$/.test(req.path)) {
        return false;
      }
      return Boolean(req.headers['content-type']?.includes('application/json'));
    },
  }),
);

if (env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
  app.use((req, res, next) => {
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
      return next();
    }
    return res.status(403).json({
      ok: false,
      error: {
        code: 'HTTPS_REQUIRED',
        message: 'HTTPS is required in production.',
      },
    });
  });
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'ctrlops-api' });
});

app.use('/api/auth', authRoutes);
app.use('/api/servers', serverRoutes);
app.use('/api/preferences', preferenceRoutes);
app.use('/api/terminal', terminalRoutes);
app.use('/api/monitor', monitorRoutes);
app.use('/api/scripts', scriptRoutes);
app.use('/api/audits', auditRoutes);
app.use('/api/servers/:serverId/audits', createServerAuditRouter());

app.use(errorHandler);

export default app;
