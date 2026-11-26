import * as opaque from '@serenity-kit/opaque';
import type { FastifyInstance } from 'fastify';
import { config } from '../config.js';
import { BadRequestError, NotFoundError, UnauthorizedError } from '../errors.js';
import { newId, type Store } from '../store.js';
import { randomSessionToken, sha256Hex } from '../server-crypto.js';
import type { User } from '../types.js';

function required(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (typeof value !== 'string' || value.length === 0) {
    throw new BadRequestError(`缺少字段 ${field}`);
  }
  return value;
}

function userIdentifier(tenantId: string, email: string): string {
  return `${tenantId}::${email}`;
}

/**
 * OPAQUE 认证路由。
 * 注意：生产环境中 tenantId/email 必须来自一次性邀请令牌，而不是客户端自由填写；
 * 否则任意人可为任意租户注册。此处保留直传是为了骨架可独立验证，接入邀请流程时收紧。
 */
export function registerAuthRoutes(app: FastifyInstance, store: Store): void {
  const serverSetup = process.env.OPAQUE_SERVER_SETUP ?? opaque.server.createSetup();

  app.get('/health', async () => ({
    ok: true,
    persistentSetup: Boolean(process.env.OPAQUE_SERVER_SETUP),
    note: '未设置 OPAQUE_SERVER_SETUP 时进程重启会使已注册用户失效，仅限开发验证',
  }));

  app.post('/auth/register/start', async (request) => {
    const body = request.body as Record<string, unknown>;
    const tenantId = required(body, 'tenantId');
    const email = required(body, 'email');
    const registrationRequest = required(body, 'registrationRequest');
    if (!(await store.getTenant(tenantId))) throw new NotFoundError('租户不存在');

    const { registrationResponse } = opaque.server.createRegistrationResponse({
      serverSetup,
      userIdentifier: userIdentifier(tenantId, email),
      registrationRequest,
    });
    return { registrationResponse };
  });

  app.post('/auth/register/finish', async (request) => {
    const body = request.body as Record<string, unknown>;
    const tenantId = required(body, 'tenantId');
    const email = required(body, 'email');
    const registrationRecord = required(body, 'registrationRecord');

    const existing = await store.getUserByEmail(tenantId, email);
    const user: User = existing ?? {
      id: newId(),
      tenantId,
      email,
      active: true,
      createdAt: new Date().toISOString(),
    };
    const updated: User = {
      ...user,
      opaqueRecord: registrationRecord,
      wrappedUk: typeof body.wrappedUk === 'string' ? body.wrappedUk : user.wrappedUk,
      kekWrappedUk: typeof body.kekWrappedUk === 'string' ? body.kekWrappedUk : user.kekWrappedUk,
      kekSalt: typeof body.kekSalt === 'string' ? body.kekSalt : user.kekSalt,
      roleCipher: typeof body.roleCipher === 'string' ? body.roleCipher : user.roleCipher,
    };
    if (existing) await store.putUser(updated);
    else await store.createUser(updated);
    return { ok: true, userId: user.id };
  });

  app.post('/auth/login/start', async (request) => {
    const body = request.body as Record<string, unknown>;
    const tenantId = required(body, 'tenantId');
    const email = required(body, 'email');
    const startLoginRequest = required(body, 'startLoginRequest');
    const user = await store.getUserByEmail(tenantId, email);
    if (!user?.opaqueRecord || !user.active) throw new UnauthorizedError('用户不存在或已停用');

    const { loginResponse, serverLoginState } = opaque.server.startLogin({
      userIdentifier: userIdentifier(tenantId, email),
      registrationRecord: user.opaqueRecord,
      serverSetup,
      startLoginRequest,
    });

    const loginId = newId();
    await store.saveLoginState({
      loginId,
      tenantId,
      email,
      serverLoginState,
      expiresAt: new Date(Date.now() + config.loginStateTtlMs).toISOString(),
    });
    return { loginResponse, loginId };
  });

  app.post('/auth/login/finish', async (request) => {
    const body = request.body as Record<string, unknown>;
    const loginId = required(body, 'loginId');
    const finishLoginRequest = required(body, 'finishLoginRequest');
    const state = await store.consumeLoginState(loginId);
    if (!state) throw new UnauthorizedError('登录会话不存在或已过期');

    opaque.server.finishLogin({
      finishLoginRequest,
      serverLoginState: state.serverLoginState,
    });

    const user = await store.getUserByEmail(state.tenantId, state.email);
    if (!user?.active) throw new UnauthorizedError('用户不存在或已停用');

    // 服务端只验证 OPAQUE 证明，永远拿不到 sessionKey（它只存在于客户端）。
    const token = randomSessionToken();
    const expiresAt = new Date(Date.now() + config.sessionTtlMs).toISOString();
    await store.createSession({
      tokenHash: sha256Hex(token),
      tenantId: state.tenantId,
      userId: user.id,
      expiresAt,
    });
    return { token, expiresAt, tenantId: state.tenantId, userId: user.id };
  });
}
