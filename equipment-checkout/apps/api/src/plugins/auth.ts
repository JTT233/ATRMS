import type { FastifyInstance, FastifyRequest } from 'fastify';
import { UnauthorizedError } from '../errors.js';
import { sha256Hex } from '../server-crypto.js';
import type { Store } from '../store.js';
import type { AuthContext } from '../types.js';

declare module 'fastify' {
  interface FastifyRequest {
    auth: AuthContext | null;
  }
}

// 这些路径在会话建立之前调用，不能要求 Bearer token。
const PUBLIC_PATHS = new Set([
  '/health',
  '/auth/register/start',
  '/auth/register/finish',
  '/auth/login/start',
  '/auth/login/finish',
]);

export function registerAuth(app: FastifyInstance, store: Store): void {
  app.decorateRequest('auth', null);

  app.addHook('onRequest', async (request: FastifyRequest) => {
    const path = request.url.split('?')[0];
    if (PUBLIC_PATHS.has(path)) return;

    const header = request.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      throw new UnauthorizedError('缺少 Bearer 会话令牌');
    }
    const token = header.slice('Bearer '.length);
    if (!token) throw new UnauthorizedError('会话令牌为空');

    const tokenHash = sha256Hex(token);
    const session = await store.getSession(tokenHash);
    if (!session || session.revokedAt) {
      throw new UnauthorizedError('会话无效或已吊销');
    }
    if (new Date(session.expiresAt).getTime() <= Date.now()) {
      throw new UnauthorizedError('会话已过期');
    }

    request.auth = {
      tenantId: session.tenantId,
      userId: session.userId,
      tokenHash,
    };

    // request.auth.tenantId 由会话派生，所有后续数据访问都必须使用它。
    // 生产 Store 实现还应在事务内 SET LOCAL app.tenant_id 以启用数据库 RLS。
  });
}

export function requireAuth(request: FastifyRequest): AuthContext {
  if (!request.auth) throw new UnauthorizedError();
  return request.auth;
}
