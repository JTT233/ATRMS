import type { FastifyRequest } from 'fastify';
import { ForbiddenError, UnauthorizedError } from '../errors.js';
import type { Store } from '../store.js';
import type { Device } from '../types.js';

function hexBytes(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(hex.length / 2));
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * 验证敏感操作来自已批准且未吊销的设备。
 *
 * payload 由每个路由显式构造（例如 `update-item:<id>:<version>`），
 * 不依赖 JSON 键顺序，避免客户端与服务端规范化不一致导致的签名分歧。
 * 私钥在浏览器中为 non-extractable，服务端只有公钥。
 */
export async function verifyDeviceSignature(
  store: Store,
  request: FastifyRequest,
  payload: string,
): Promise<Device> {
  const auth = request.auth;
  if (!auth) throw new UnauthorizedError();

  const deviceId = request.headers['x-device-id'];
  const signatureHex = request.headers['x-device-signature'];
  if (typeof deviceId !== 'string' || typeof signatureHex !== 'string') {
    throw new UnauthorizedError('缺少设备签名头 X-Device-Id / X-Device-Signature');
  }

  const device = await store.getDevice(auth.tenantId, deviceId);
  if (!device || !device.approved || device.revokedAt) {
    throw new ForbiddenError('设备未获批准或已吊销');
  }
  if (device.userId !== auth.userId) {
    throw new ForbiddenError('设备不属于当前会话用户');
  }

  const publicKey = await crypto.subtle.importKey(
    'raw',
    hexBytes(device.publicKey),
    { name: 'Ed25519' },
    false,
    ['verify'],
  );
  const valid = await crypto.subtle.verify(
    'Ed25519',
    publicKey,
    hexBytes(signatureHex),
    new TextEncoder().encode(payload),
  );
  if (!valid) throw new ForbiddenError('设备签名验证失败');
  return device;
}
