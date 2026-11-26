import cors from '@fastify/cors';
import Fastify from 'fastify';
import { errorHandler } from './errors.js';
import { registerAuth } from './plugins/auth.js';
import { registerRateLimit } from './plugins/rate-limit.js';
import { registerAuditRoutes } from './routes/audit.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerCipherRoutes } from './routes/cipher.js';
import { registerDeviceRoutes } from './routes/devices.js';
import { MemoryStore, type Store } from './store.js';

declare module 'fastify' {
  interface FastifyInstance {
    store: Store;
  }
}

export interface AppOptions {
  store?: Store;
  corsOrigin?: boolean | string | string[];
}

/**
 * 组装零知识 API。Store 可注入：
 *   - 测试注入 MemoryStore；
 *   - 生产注入 PostgresStore（实现 docs/database-schema.md 的事务与 RLS 语义）。
 */
export async function createApp(options: AppOptions = {}) {
  const store = options.store ?? new MemoryStore();
  const app = Fastify({ logger: false, bodyLimit: 8 * 1024 * 1024 });

  app.setErrorHandler(errorHandler);
  app.decorate('store', store);

  await app.register(cors, {
    origin: options.corsOrigin ?? true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-Id', 'X-Device-Signature'],
  });

  registerRateLimit(app);
  registerAuth(app, store);

  registerAuthRoutes(app, store);
  registerDeviceRoutes(app, store);
  registerCipherRoutes(app, store);
  registerAuditRoutes(app, store);

  return app;
}
