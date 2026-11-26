import type { FastifyInstance } from 'fastify';
import { BadRequestError, ConflictError, NotFoundError } from '../errors.js';
import { requireAuth } from '../plugins/auth.js';
import { verifyDeviceSignature } from '../plugins/device-signature.js';
import { computeAuditHash, sha256Hex } from '../server-crypto.js';
import type { Store } from '../store.js';

/**
 * 审计链路由。关键点：
 *   - hash 由服务端用服务端时间戳计算，客户端无法操纵时间；
 *   - 客户端提交 expectedPrevHash，Store 在锁内校验并原子推进链头；
 *   - 服务端无法伪造有效链（无 AK），也无法删除单条而不被验证端发现。
 */
export function registerAuditRoutes(app: FastifyInstance, store: Store): void {
  app.post('/v1/audit', async (request) => {
    const auth = requireAuth(request);
    const body = request.body as Record<string, unknown>;
    const sealedEvent = body.sealedEvent;
    const aad = body.aad;
    const expectedPrevHash = body.expectedPrevHash;
    if (typeof sealedEvent !== 'string' || typeof aad !== 'string' || typeof expectedPrevHash !== 'string') {
      throw new BadRequestError('缺少 sealedEvent / aad / expectedPrevHash');
    }

    const device = await verifyDeviceSignature(
      store,
      request,
      `audit:${expectedPrevHash}:${sha256Hex(sealedEvent)}`,
    );

    const head = await store.getChainHead(auth.tenantId);
    if (!head) throw new NotFoundError('租户审计链不存在');
    if (head.lastHash !== expectedPrevHash) {
      throw new ConflictError('审计链前序哈希不匹配，请基于最新链头重算后重试');
    }

    // 时间戳必须是服务端时间；hash 拼接顺序与 packages/crypto 严格一致。
    const timestamp = new Date().toISOString();
    const hash = computeAuditHash(expectedPrevHash, sealedEvent, timestamp, aad);
    return store.appendAudit({
      tenantId: auth.tenantId,
      ...(typeof body.vaultId === 'string' ? { vaultId: body.vaultId } : {}),
      sealedEvent,
      aad,
      expectedPrevHash,
      hash,
      deviceId: device.id,
    });
  });

  app.get('/v1/audit', async (request) => {
    const auth = requireAuth(request);
    const query = request.query as Record<string, string | undefined>;
    const afterId = Number(query.afterId ?? 0);
    const limit = Math.min(Number(query.limit ?? 100), 500);
    if (!Number.isInteger(afterId) || !Number.isInteger(limit)) {
      throw new BadRequestError('afterId / limit 必须是整数');
    }
    return {
      head: await store.getChainHead(auth.tenantId),
      events: await store.listAuditEvents(auth.tenantId, afterId, limit),
    };
  });
}
