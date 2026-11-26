import { createHash, randomBytes } from 'node:crypto';
import { config } from './config.js';
import { BadRequestError } from './errors.js';

/**
 * 服务端只做哈希与随机令牌，从不接触 TK/UK/VK/DEK/AK 或任何明文业务内容。
 * 本文件的 auditHash 实现必须与 packages/crypto/src/index.ts 中的 auditHash
 * 逐字节一致；api.test.ts 有跨包一致性测试守住这一点。
 */

export function sha256Hex(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
  return createHash('sha256').update(bytes).digest('hex');
}

export function randomHex(byteLength: number): string {
  return randomBytes(byteLength).toString('hex');
}

export function randomSessionToken(): string {
  return randomBytes(32).toString('base64url');
}

export function genesisHash(tenantId: string): string {
  return sha256Hex(config.audit.genesisLabel + tenantId);
}

interface SealedEnvelope {
  v?: number;
  alg?: string;
  iv?: string;
  ct?: string;
  tag?: string;
  aad?: string;
}

/**
 * 信封传输约定：客户端上传的 sealed* 字段是
 *   hex( UTF8( JSON.stringify({ v, alg, iv, ct, tag, aad }) ) )
 * 其中 iv/ct/tag 自身也是 hex 字符串。信封格式是公开协议，不含业务明文。
 */
export function extractSealedParts(sealedHex: string): { ct: Buffer; tag: Buffer } {
  let envelope: SealedEnvelope;
  try {
    const json = Buffer.from(sealedHex, 'hex').toString('utf8');
    envelope = JSON.parse(json) as SealedEnvelope;
  } catch {
    throw new BadRequestError('密文信封格式不合法');
  }
  if (typeof envelope.ct !== 'string' || typeof envelope.tag !== 'string') {
    throw new BadRequestError('密文信封缺少 ct 或 tag');
  }
  return { ct: Buffer.from(envelope.ct, 'hex'), tag: Buffer.from(envelope.tag, 'hex') };
}

/** 与 packages/crypto 的 auditHash 完全相同的拼接顺序与长度编码。 */
export function computeAuditHash(
  prevHex: string,
  sealedHex: string,
  timestamp: string,
  aad: string,
): string {
  const { ct, tag } = extractSealedParts(sealedHex);
  const aadBytes = Buffer.from(aad, 'utf8');
  const lengthBytes = Buffer.from(String(aadBytes.length), 'utf8');
  const timeBytes = Buffer.from(timestamp, 'utf8');
  const parts = [
    Buffer.from(prevHex, 'hex'),
    lengthBytes,
    aadBytes,
    ct,
    tag,
    timeBytes,
  ];
  return createHash('sha256').update(Buffer.concat(parts)).digest('hex');
}
