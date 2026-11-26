import type { FastifyInstance } from 'fastify';
import { BadRequestError, ForbiddenError, NotFoundError } from '../errors.js';
import { requireAuth } from '../plugins/auth.js';
import { verifyDeviceSignature } from '../plugins/device-signature.js';
import { newId, type Store } from '../store.js';
import type { Device } from '../types.js';

/** Ed25519 公钥 32 字节 → 64 个十六进制字符。 */
function isPublicKeyHex(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value);
}

/**
 * 设备登记路由。
 * 新设备登记本身不要求已有设备签名（否则无法引导第一台设备），
 * 但登记后处于 approved=false，必须由已批准设备或组织恢复流程批准。
 */
export function registerDeviceRoutes(app: FastifyInstance, store: Store): void {
  app.post('/v1/devices', async (request) => {
    const auth = requireAuth(request);
    const body = request.body as Record<string, unknown>;
    if (!isPublicKeyHex(body.publicKey)) throw new BadRequestError('publicKey 必须是 32 字节十六进制');

    const existing = await store.listDevices(auth.tenantId);
    if (existing.some((d) => d.publicKey.toLowerCase() === (body.publicKey as string).toLowerCase())) {
      return existing.find((d) => d.publicKey.toLowerCase() === (body.publicKey as string).toLowerCase());
    }

    const device: Device = {
      id: newId(),
      tenantId: auth.tenantId,
      userId: auth.userId,
      publicKey: body.publicKey.toLowerCase(),
      labelCipher: typeof body.labelCipher === 'string' ? body.labelCipher : undefined,
      approved: false,
      createdAt: new Date().toISOString(),
    };
    return store.createDevice(device);
  });

  app.get('/v1/devices', async (request) => {
    const auth = requireAuth(request);
    return { devices: await store.listDevices(auth.tenantId) };
  });

  app.post('/v1/devices/:id/approve', async (request) => {
    const auth = requireAuth(request);
    const { id } = request.params as { id: string };
    const approver = await verifyDeviceSignature(store, request, `approve-device:${id}`);
    const target = await store.getDevice(auth.tenantId, id);
    if (!target) throw new NotFoundError('设备不存在');
    if (target.tenantId !== auth.tenantId) throw new ForbiddenError('跨租户设备操作被拒绝');
    return store.putDevice({
      ...target,
      approved: true,
      approvedBy: approver.id,
    });
  });

  app.post('/v1/devices/:id/revoke', async (request) => {
    const auth = requireAuth(request);
    const { id } = request.params as { id: string };
    await verifyDeviceSignature(store, request, `revoke-device:${id}`);
    const target = await store.getDevice(auth.tenantId, id);
    if (!target) throw new NotFoundError('设备不存在');
    return store.putDevice({ ...target, revokedAt: new Date().toISOString() });
  });
}
