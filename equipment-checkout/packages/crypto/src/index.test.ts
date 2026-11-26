import { describe, expect, it } from 'vitest';
import {
  auditHash,
  combineTenantKey,
  contextAad,
  deriveKekFromOpaque,
  deriveLocalKek,
  exportRawKey,
  fromHex,
  generateAesKey,
  hkdf,
  importAesKey,
  open,
  randomBytes,
  seal,
  sha256,
  splitTenantKey,
  toHex,
  unwrapKey,
  wrapKey,
} from './index.js';

describe('随机与密钥生成', () => {
  it('生成指定长度的随机字节且两次不同', () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    expect(a).toHaveLength(32);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it('AES-256 密钥可导出再导入', async () => {
    const key = await generateAesKey();
    const raw = await exportRawKey(key);
    expect(raw).toHaveLength(32);
    const imported = await importAesKey(raw);
    expect(imported.algorithm.name).toBe('AES-GCM');
  });
});

describe('密文信封', () => {
  const ctx = {
    tenantId: 'tenant-a',
    vaultId: 'vault-1',
    type: 'item' as const,
    objectId: 'item-1',
    version: 1,
  };

  it('加解密往返成功', async () => {
    const key = await generateAesKey();
    const plaintext = new TextEncoder().encode('显微镜 A-12');
    const sealed = await seal(key, plaintext, contextAad(ctx));
    const opened = await open(key, sealed, contextAad(ctx));
    expect(new TextDecoder().decode(opened)).toBe('显微镜 A-12');
    expect(sealed.iv).toHaveLength(12);
    expect(sealed.tag).toHaveLength(16);
  });

  it('AAD 不匹配时拒绝解密（防止跨租户/跨对象调包）', async () => {
    const key = await generateAesKey();
    const sealed = await seal(key, new TextEncoder().encode('secret'), contextAad(ctx));
    const wrongCtx = { ...ctx, tenantId: 'tenant-b' };
    await expect(open(key, sealed, contextAad(wrongCtx))).rejects.toThrow(/AAD/);
  });

  it('密文被篡改时 GCM 校验失败', async () => {
    const key = await generateAesKey();
    const sealed = await seal(key, new TextEncoder().encode('secret'), contextAad(ctx));
    sealed.ct[0] ^= 1;
    await expect(open(key, sealed, contextAad(ctx))).rejects.toThrow();
  });

  it('不同密钥加密同一明文得到不同密文', async () => {
    const plaintext = new TextEncoder().encode('same');
    const a = await seal(await generateAesKey(), plaintext, contextAad(ctx));
    const b = await seal(await generateAesKey(), plaintext, contextAad(ctx));
    expect(toHex(a.ct)).not.toBe(toHex(b.ct));
  });
});

describe('密钥包裹', () => {
  it('KEK 包裹/解包 DEK 成功，purpose 错则失败', async () => {
    const kek = await generateAesKey();
    const dek = await exportRawKey(await generateAesKey());
    const wrapped = await wrapKey(kek, dek, 'vk', 'vault-1');
    const unwrapped = await unwrapKey(kek, wrapped, 'vk', 'vault-1');
    expect(toHex(await exportRawKey(unwrapped))).toBe(toHex(dek));
    await expect(unwrapKey(kek, wrapped, 'ak', 'vault-1')).rejects.toThrow(/AAD/);
  });
});

describe('密钥派生', () => {
  it('HKDF 确定且 info 不同结果不同', async () => {
    const ikm = randomBytes(32);
    const salt = randomBytes(16);
    expect(toHex(await hkdf(ikm, salt, 'kek-v1'))).toBe(toHex(await hkdf(ikm, salt, 'kek-v1')));
    expect(toHex(await hkdf(ikm, salt, 'kek-v1'))).not.toBe(toHex(await hkdf(ikm, salt, 'uk-wrap-v1')));
  });

  it('OPAQUE sessionKey 派生 KEK', async () => {
    const sessionKey = randomBytes(32);
    const salt = randomBytes(16);
    expect(await deriveKekFromOpaque(sessionKey, salt)).toHaveLength(32);
  });

  it('Argon2id 离线派生确定且输出 32 字节', async () => {
    const salt = randomBytes(16);
    const a = await deriveLocalKek('correct horse battery staple', salt);
    const b = await deriveLocalKek('correct horse battery staple', salt);
    expect(a).toHaveLength(32);
    expect(toHex(a)).toBe(toHex(b));
  });
});

describe('Shamir 2-of-3 恢复', () => {
  it('任意两份分片可重构，哈希校验通过', async () => {
    const tk = randomBytes(32);
    const expected = toHex(await sha256(tk));
    const shares = await splitTenantKey(tk);
    expect(shares).toHaveLength(3);
    const recovered = await combineTenantKey([shares[0], shares[2]], expected);
    expect(toHex(recovered)).toBe(toHex(tk));
  });

  it('单份分片重构会被哈希校验拒绝', async () => {
    const tk = randomBytes(32);
    const expected = toHex(await sha256(tk));
    const shares = await splitTenantKey(tk);
    await expect(combineTenantKey([shares[0]], expected)).rejects.toThrow();
  });

  it('错误哈希会使重构失败', async () => {
    const tk = randomBytes(32);
    const shares = await splitTenantKey(tk);
    await expect(combineTenantKey([shares[0], shares[1]], toHex(randomBytes(32)))).rejects.toThrow(/校验失败/);
  });
});

describe('审计哈希链', () => {
  it('链式哈希确定，篡改密文后重算不一致', async () => {
    const key = await generateAesKey();
    const a = await seal(key, new TextEncoder().encode('event-1'), 'audit:1');
    const b = await seal(key, new TextEncoder().encode('event-2'), 'audit:2');
    const h1 = await auditHash(null, a, '2026-11-24T10:00:00Z', 'audit:1');
    const h2 = await auditHash(h1, b, '2026-11-24T10:01:00Z', 'audit:2');
    expect(toHex(h2)).toBe(toHex(await auditHash(h1, b, '2026-11-24T10:01:00Z', 'audit:2')));

    const tampered = { ...b, ct: new Uint8Array(b.ct) };
    tampered.ct[0] ^= 1;
    const h2Tampered = await auditHash(h1, tampered, '2026-11-24T10:01:00Z', 'audit:2');
    expect(toHex(h2Tampered)).not.toBe(toHex(h2));
  });
});

describe('十六进制工具', () => {
  it('toHex / fromHex 往返', () => {
    const bytes = randomBytes(16);
    expect(toHex(fromHex(toHex(bytes)))).toBe(toHex(bytes));
  });
});
