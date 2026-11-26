import { createHash } from 'node:crypto';
import * as opaque from '@serenity-kit/opaque';
import { generateAesKey, seal, toHex, auditHash as cryptoAuditHash } from '@equipment/crypto';
import type { FastifyInstance } from 'fastify';
import type { Response } from 'light-my-request';
import { describe, expect, it } from 'vitest';
import { createApp } from './app.js';
import { computeAuditHash, genesisHash } from './server-crypto.js';
import { MemoryStore, newId } from './store.js';
import type { Item } from './types.js';

const TENANT_A = '11111111-1111-4111-8111-111111111111';
const TENANT_B = '22222222-2222-4222-8222-222222222222';
const PASSWORD = 'correct-horse-battery-staple';

async function seedTenant(store: MemoryStore, tenantId: string): Promise<void> {
  await store.createTenant({
    id: tenantId,
    tkHash: genesisHash(tenantId),
    recoveryThreshold: 2,
    recoveryShareCount: 3,
    billingStatus: 'trial',
    createdAt: new Date().toISOString(),
  });
}

/** 完成一次真实 OPAQUE 注册 + 登录，返回会话 token 与 userId。 */
async function registerAndLogin(
  app: FastifyInstance,
  tenantId: string,
  email: string,
): Promise<{ token: string; userId: string }> {
  const reg = opaque.client.startRegistration({ password: PASSWORD });
  const start = await app.inject({
    method: 'POST',
    url: '/auth/register/start',
    payload: { tenantId, email, registrationRequest: reg.registrationRequest },
  });
  expect(start.statusCode).toBe(200);

  const finishReg = opaque.client.finishRegistration({
    clientRegistrationState: reg.clientRegistrationState,
    registrationResponse: start.json().registrationResponse,
    password: PASSWORD,
  });
  const stored = await app.inject({
    method: 'POST',
    url: '/auth/register/finish',
    payload: { tenantId, email, registrationRecord: finishReg.registrationRecord },
  });
  expect(stored.statusCode).toBe(200);

  const login = opaque.client.startLogin({ password: PASSWORD });
  const loginStart = await app.inject({
    method: 'POST',
    url: '/auth/login/start',
    payload: { tenantId, email, startLoginRequest: login.startLoginRequest },
  });
  expect(loginStart.statusCode).toBe(200);
  const { loginResponse, loginId } = loginStart.json();

  const loginFinish = opaque.client.finishLogin({
    clientLoginState: login.clientLoginState,
    loginResponse,
    password: PASSWORD,
  });
  expect(loginFinish).toBeDefined();
  const done = await app.inject({
    method: 'POST',
    url: '/auth/login/finish',
    payload: { loginId, finishLoginRequest: loginFinish!.finishLoginRequest },
  });
  expect(done.statusCode).toBe(200);
  return { token: done.json().token as string, userId: done.json().userId as string };
}

interface Harness {
  app: FastifyInstance;
  store: MemoryStore;
  tenantId: string;
  token: string;
  userId: string;
  deviceId: string;
  privateKey: CryptoKey;
}

async function harness(tenantId = TENANT_A): Promise<Harness> {
  const store = new MemoryStore();
  const app = await createApp({ store });
  await seedTenant(store, tenantId);
  const { token, userId } = await registerAndLogin(app, tenantId, `admin-${tenantId}@example.com`);

  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKey = toHex(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
  const device = await store.createDevice({
    id: newId(),
    tenantId,
    userId,
    publicKey,
    approved: true,
    createdAt: new Date().toISOString(),
  });
  return { app, store, tenantId, token, userId, deviceId: device.id, privateKey: pair.privateKey };
}

async function signed(
  h: Harness,
  method: 'POST' | 'PATCH' | 'GET',
  url: string,
  payloadForSignature: string,
  body?: unknown,
): Promise<Response> {
  const signature = await crypto.subtle.sign(
    'Ed25519',
    h.privateKey,
    new TextEncoder().encode(payloadForSignature),
  );
  const headers = {
    authorization: `Bearer ${h.token}`,
    'x-device-id': h.deviceId,
    'x-device-signature': toHex(new Uint8Array(signature)),
  };
  if (body === undefined) return await h.app.inject({ method, url, headers });
  return await h.app.inject({ method, url, headers, payload: body as Record<string, unknown> });
}

function sealedEnvelope(ctHex: string, tagHex: string, aad: string): string {
  const json = JSON.stringify({
    v: 1,
    alg: 'AES-256-GCM',
    iv: '00'.repeat(12),
    ct: ctHex,
    tag: tagHex,
    aad,
  });
  return Buffer.from(json, 'utf8').toString('hex');
}

async function createVault(h: Harness): Promise<string> {
  const wrappedVk = 'ab'.repeat(32);
  const response = await signed(h, 'POST', '/v1/vaults', `create-vault:${sha256Text(wrappedVk)}`, {
    wrappedVk,
    labelCipher: 'cc'.repeat(8),
  });
  expect(response.statusCode).toBe(200);
  return response.json().id as string;
}

function sha256Text(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

async function createItem(h: Harness, vaultId: string): Promise<Item> {
  const sealedField = sealedEnvelope('01'.repeat(8), '02'.repeat(16), '{"type":"item"}');
  const response = await signed(
    h,
    'POST',
    '/v1/items',
    `create-item:${vaultId}:${sha256Text(sealedField)}`,
    { vaultId, wrappedDek: 'dd'.repeat(32), sealedField },
  );
  expect(response.statusCode).toBe(200);
  return response.json() as Item;
}

describe('OPAQUE 认证与会话', () => {
  it('正确口令完成注册/登录并返回会话 token', async () => {
    const h = await harness();
    expect(h.token).toBeTypeOf('string');
    expect(h.token.length).toBeGreaterThan(20);
    await h.app.close();
  });

  it('错误口令不能登录；无 token 访问受保护路由被拒绝', async () => {
    const h = await harness();
    const bad = opaque.client.startLogin({ password: 'wrong-password' });
    const badStart = await h.app.inject({
      method: 'POST',
      url: '/auth/login/start',
      payload: { tenantId: h.tenantId, email: `admin-${h.tenantId}@example.com`, startLoginRequest: bad.startLoginRequest },
    });
    const badFinish = opaque.client.finishLogin({
      clientLoginState: bad.clientLoginState,
      loginResponse: badStart.json().loginResponse,
      password: 'wrong-password',
    });
    expect(badFinish).toBeUndefined();

    const noAuth = await h.app.inject({ method: 'GET', url: '/v1/vaults' });
    expect(noAuth.statusCode).toBe(401);
    await h.app.close();
  });
});

describe('租户隔离', () => {
  it('A 租户会话无法读取 B 租户的器材或二维码', async () => {
    const a = await harness(TENANT_A);
    const bStore = new MemoryStore();
    const bApp = await createApp({ store: bStore });
    await seedTenant(bStore, TENANT_B);
    const bSession = await registerAndLogin(bApp, TENANT_B, `admin-${TENANT_B}@example.com`);

    const bVault = await bStore.createVault({
      id: newId(), tenantId: TENANT_B, wrappedVk: 'aa'.repeat(32), createdAt: new Date().toISOString(),
    });
    const bItem: Item = {
      id: newId(), tenantId: TENANT_B, vaultId: bVault.id, wrappedDek: 'bb'.repeat(32),
      sealedField: 'cc'.repeat(16), qrToken: 'fe'.repeat(16), openLoanFlag: 0,
      version: 1, nonceCount: 0, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    };
    await bStore.createItem(bItem);

    const byId = await a.app.inject({
      method: 'GET', url: `/v1/items/${bItem.id}`,
      headers: { authorization: `Bearer ${a.token}` },
    });
    expect(byId.statusCode).toBe(404);

    const byQr = await a.app.inject({
      method: 'GET', url: `/v1/items/by-qr/${bItem.qrToken}`,
      headers: { authorization: `Bearer ${a.token}` },
    });
    expect(byQr.statusCode).toBe(404);

    expect(bSession.token).toBeTypeOf('string');
    await a.app.close();
    await bApp.close();
  });
});

describe('设备签名', () => {
  it('缺少签名或签名错误时拒绝写操作', async () => {
    const h = await harness();
    const vaultId = await createVault(h);
    const wrappedVk = 'ab'.repeat(32);

    const missing = await h.app.inject({
      method: 'POST', url: '/v1/vaults',
      headers: { authorization: `Bearer ${h.token}` },
      payload: { wrappedVk },
    });
    expect(missing.statusCode).toBe(401);

    const bad = await h.app.inject({
      method: 'POST', url: '/v1/items',
      headers: {
        authorization: `Bearer ${h.token}`,
        'x-device-id': h.deviceId,
        'x-device-signature': '00'.repeat(64),
      },
      payload: { vaultId, wrappedDek: 'dd'.repeat(32), sealedField: 'ee'.repeat(16) },
    });
    expect(bad.statusCode).toBe(403);
    await h.app.close();
  });
});

describe('乐观锁与借还状态', () => {
  it('版本冲突返回 409；借出与归还原子更新器材状态', async () => {
    const h = await harness();
    const vaultId = await createVault(h);
    const item = await createItem(h, vaultId);

    const ok = await signed(h, 'PATCH', `/v1/items/${item.id}`, `update-item:${item.id}:1`, {
      version: 1, sealedField: '11'.repeat(16),
    });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().version).toBe(2);

    const conflict = await signed(h, 'PATCH', `/v1/items/${item.id}`, `update-item:${item.id}:1`, {
      version: 1, sealedField: '22'.repeat(16),
    });
    expect(conflict.statusCode).toBe(409);

    const sealedRecord = sealedEnvelope('33'.repeat(8), '44'.repeat(16), '{"type":"loan"}');
    const loan = await signed(
      h, 'POST', '/v1/loans', `create-loan:${item.id}:${sha256Text(sealedRecord)}`,
      { itemId: item.id, vaultId, sealedRecord },
    );
    expect(loan.statusCode).toBe(200);
    const loanId = loan.json().id as string;
    expect((await h.store.getItem(h.tenantId, item.id))?.openLoanFlag).toBe(1);

    const secondSealed = '55'.repeat(16);
    const secondLoan = await signed(
      h, 'POST', '/v1/loans', `create-loan:${item.id}:${sha256Text(secondSealed)}`,
      { itemId: item.id, vaultId, sealedRecord: secondSealed },
    );
    expect(secondLoan.statusCode).toBe(409);

    const returned = await signed(
      h, 'POST', `/v1/loans/${loanId}/return`, `return-loan:${loanId}:1`,
      { version: 1, sealedRecord: '66'.repeat(16) },
    );
    expect(returned.statusCode).toBe(200);
    expect((await h.store.getItem(h.tenantId, item.id))?.openLoanFlag).toBe(0);
    await h.app.close();
  });
});

describe('审计链', () => {
  it('连续追加哈希链接正确；错误前序哈希被拒绝', async () => {
    const h = await harness();
    const head = await h.store.getChainHead(h.tenantId);
    expect(head?.lastHash).toBe(genesisHash(h.tenantId));

    const sealed1 = sealedEnvelope('77'.repeat(8), '88'.repeat(16), '{"type":"audit","seq":1}');
    const aad1 = '{"type":"audit","seq":1}';
    const r1 = await unsignedAudit(h, sealed1, aad1, head!.lastHash);
    expect(r1.statusCode).toBe(200);
    const event1 = r1.json();
    expect(event1.prevHash).toBe(head!.lastHash);
    expect(event1.hash).toMatch(/^[0-9a-f]{64}$/);

    const sealed2 = sealedEnvelope('99'.repeat(8), 'aa'.repeat(16), '{"type":"audit","seq":2}');
    const aad2 = '{"type":"audit","seq":2}';
    const stale = await unsignedAudit(h, sealed2, aad2, head!.lastHash);
    expect(stale.statusCode).toBe(409);

    const r2 = await unsignedAudit(h, sealed2, aad2, event1.hash);
    expect(r2.statusCode).toBe(200);
    expect(r2.json().prevHash).toBe(event1.hash);
    expect(r2.json().id).toBe(event1.id + 1);
    await h.app.close();
  });

  it('服务端哈希与加密核心包逐字节一致', async () => {
    const key = await generateAesKey();
    const aad = '{"tenantId":"t","vaultId":"v","type":"audit","objectId":"o","version":1}';
    const sealed = await seal(key, new TextEncoder().encode('hello'), aad);
    const prev = new Uint8Array(32).fill(7);
    const timestamp = '2026-11-24T00:00:00.000Z';
    const expected = toHex(await cryptoAuditHash(prev, sealed, timestamp, aad));

    const sealedHex = sealedEnvelope(toHex(sealed.ct), toHex(sealed.tag), aad);
    const actual = computeAuditHash(toHex(prev), sealedHex, timestamp, aad);
    expect(actual).toBe(expected);
  });
});

async function unsignedAudit(h: Harness, sealedEvent: string, aad: string, expectedPrevHash: string): Promise<Response> {
  return await signed(
    h, 'POST', '/v1/audit', `audit:${expectedPrevHash}:${sha256Text(sealedEvent)}`,
    { sealedEvent, aad, expectedPrevHash },
  );
}

describe('限流', () => {
  it('超过固定窗口上限返回 429', async () => {
    const app = await createApp({ store: new MemoryStore() });
    for (let i = 0; i < 300; i += 1) {
      const r = await app.inject({ method: 'GET', url: '/health' });
      expect(r.statusCode).toBe(200);
    }
    const blocked = await app.inject({ method: 'GET', url: '/health' });
    expect(blocked.statusCode).toBe(429);
    await app.close();
  });
});
