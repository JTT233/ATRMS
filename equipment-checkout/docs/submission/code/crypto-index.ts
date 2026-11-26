import { argon2id } from 'hash-wasm';
import { combine, split } from 'shamir-secret-sharing';

export const ENVELOPE_VERSION = 1 as const;
const TAG_LENGTH = 16;
const IV_LENGTH = 12;
const KEY_LENGTH = 32;

const encoder = new TextEncoder();

export type ObjectType = 'item' | 'loan' | 'audit' | 'index' | 'photo' | 'thumbnail';

export interface EnvelopeContext {
  tenantId: string;
  vaultId: string;
  type: ObjectType;
  objectId: string;
  version: number;
}

export interface Sealed {
  v: 1;
  alg: 'AES-256-GCM';
  iv: Uint8Array;
  ct: Uint8Array;
  tag: Uint8Array;
  aad: string;
}

function buf(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function contextAad(ctx: EnvelopeContext): string {
  return JSON.stringify({
    tenantId: ctx.tenantId,
    vaultId: ctx.vaultId,
    type: ctx.type,
    objectId: ctx.objectId,
    version: ctx.version,
  });
}

export function wrapAad(purpose: string, objectId: string): string {
  return `wrap-v1:${purpose}:${objectId}`;
}

export async function generateAesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function importAesKey(raw: Uint8Array, extractable = false): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', buf(raw), { name: 'AES-GCM' }, extractable, ['encrypt', 'decrypt']);
}

export async function exportRawKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

export async function seal(key: CryptoKey, plaintext: Uint8Array, aad: string): Promise<Sealed> {
  const iv = randomBytes(IV_LENGTH);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: buf(iv), additionalData: buf(encoder.encode(aad)) },
      key,
      buf(plaintext),
    ),
  );
  return {
    v: ENVELOPE_VERSION,
    alg: 'AES-256-GCM',
    iv,
    ct: encrypted.slice(0, encrypted.length - TAG_LENGTH),
    tag: encrypted.slice(encrypted.length - TAG_LENGTH),
    aad,
  };
}

export async function open(key: CryptoKey, sealed: Sealed, expectedAad?: string): Promise<Uint8Array> {
  if (sealed.v !== ENVELOPE_VERSION || sealed.alg !== 'AES-256-GCM') {
    throw new Error('不支持的密文信封版本或算法');
  }
  if (expectedAad !== undefined && sealed.aad !== expectedAad) {
    throw new Error('AAD 上下文不匹配，拒绝解密');
  }
  const combined = new Uint8Array(sealed.ct.length + sealed.tag.length);
  combined.set(sealed.ct, 0);
  combined.set(sealed.tag, sealed.ct.length);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: buf(sealed.iv), additionalData: buf(encoder.encode(sealed.aad)) },
      key,
      combined,
    ),
  );
}

export async function wrapKey(kek: CryptoKey, rawKey: Uint8Array, purpose: string, objectId: string): Promise<Sealed> {
  return seal(kek, rawKey, wrapAad(purpose, objectId));
}

export async function unwrapKey(kek: CryptoKey, sealed: Sealed, purpose: string, objectId: string): Promise<CryptoKey> {
  const raw = await open(kek, sealed, wrapAad(purpose, objectId));
  return importAesKey(raw, true);
}

export async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string, lengthBytes = KEY_LENGTH): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey('raw', buf(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: buf(salt), info: buf(encoder.encode(info)) },
    base,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

export function deriveKekFromOpaque(sessionKey: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  return hkdf(sessionKey, salt, 'kek-v1');
}

export function deriveLocalKek(passphrase: string, salt: Uint8Array): Promise<Uint8Array> {
  return argon2id({
    password: passphrase,
    salt,
    parallelism: 4,
    iterations: 3,
    memorySize: 65536,
    hashLength: KEY_LENGTH,
    outputType: 'binary',
  });
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf(data)));
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/.{2}/g)?.map((b) => parseInt(b, 16)) ?? []);
}

export async function auditHash(
  prev: Uint8Array | null,
  sealed: Sealed,
  timestamp: string,
  aad: string,
): Promise<Uint8Array> {
  const aadBytes = encoder.encode(aad);
  const lengthBytes = encoder.encode(String(aadBytes.length));
  const timeBytes = encoder.encode(timestamp);
  const parts = [
    prev ?? new Uint8Array(32),
    lengthBytes,
    aadBytes,
    sealed.ct,
    sealed.tag,
    timeBytes,
  ];
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return sha256(joined);
}

export async function splitTenantKey(tk: Uint8Array): Promise<Uint8Array[]> {
  return split(tk, 3, 2);
}

export async function combineTenantKey(shares: Uint8Array[], expectedTkHashHex: string): Promise<Uint8Array> {
  const recovered = await combine(shares);
  const actual = toHex(await sha256(recovered));
  if (actual !== expectedTkHashHex) {
    throw new Error('恢复分片校验失败：重构出的主密钥哈希不匹配');
  }
  return recovered;
}

export async function deviceKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
}

export async function signWithDevice(privateKey: CryptoKey, payload: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, buf(payload)));
}

export async function verifyWithDevice(publicKey: CryptoKey, payload: Uint8Array, signature: Uint8Array): Promise<boolean> {
  return crypto.subtle.verify('Ed25519', publicKey, buf(signature), buf(payload));
}
