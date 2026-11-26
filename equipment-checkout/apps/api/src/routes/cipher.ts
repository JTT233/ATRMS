import type { FastifyInstance } from 'fastify';
import { BadRequestError, NotFoundError } from '../errors.js';
import { requireAuth } from '../plugins/auth.js';
import { verifyDeviceSignature } from '../plugins/device-signature.js';
import { newId, type Store } from '../store.js';
import { randomHex, sha256Hex } from '../server-crypto.js';
import type { Item, Loan, Vault } from '../types.js';

function req(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (typeof value !== 'string' || value.length === 0) {
    throw new BadRequestError(`缺少字段 ${field}`);
  }
  return value;
}

function opt(body: Record<string, unknown>, field: string): string | undefined {
  const value = body[field];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function reqVersion(body: Record<string, unknown>): number {
  const value = body.version;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw new BadRequestError('缺少有效的 version');
  }
  return value;
}

/**
 * 密文 CRUD 路由。服务端只做：认证 → 设备签名 → 租户归属校验 →
 * 版本/状态原子更新 → 原样存取密文字节。从不解析任何业务内容。
 */
export function registerCipherRoutes(app: FastifyInstance, store: Store): void {
  // ---- Vault ----
  app.post('/v1/vaults', async (request) => {
    const auth = requireAuth(request);
    const body = request.body as Record<string, unknown>;
    const wrappedVk = req(body, 'wrappedVk');
    await verifyDeviceSignature(store, request, `create-vault:${sha256Hex(wrappedVk)}`);
    if (body.parentId && !(await store.getVault(auth.tenantId, req(body, 'parentId')))) {
      throw new NotFoundError('父保险库不存在');
    }
    const vault: Vault = {
      id: newId(),
      tenantId: auth.tenantId,
      wrappedVk,
      labelCipher: opt(body, 'labelCipher'),
      parentId: opt(body, 'parentId'),
      createdAt: new Date().toISOString(),
    };
    return store.createVault(vault);
  });

  app.get('/v1/vaults', async (request) => {
    const auth = requireAuth(request);
    return { vaults: await store.listVaults(auth.tenantId) };
  });

  // ---- Item ----
  app.post('/v1/items', async (request) => {
    const auth = requireAuth(request);
    const body = request.body as Record<string, unknown>;
    const vaultId = req(body, 'vaultId');
    const sealedField = req(body, 'sealedField');
    const wrappedDek = req(body, 'wrappedDek');
    await verifyDeviceSignature(store, request, `create-item:${vaultId}:${sha256Hex(sealedField)}`);
    if (!(await store.getVault(auth.tenantId, vaultId))) throw new NotFoundError('保险库不存在');

    const item: Item = {
      id: newId(),
      tenantId: auth.tenantId,
      vaultId,
      wrappedDek,
      sealedField,
      thumbCipher: opt(body, 'thumbCipher'),
      photoCipher: opt(body, 'photoCipher'),
      qrToken: randomHex(16), // 128-bit opaque token，服务端生成，无业务含义
      openLoanFlag: 0,
      version: 1,
      nonceCount: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    return store.createItem(item);
  });

  app.get('/v1/items', async (request) => {
    const auth = requireAuth(request);
    const query = request.query as Record<string, string | undefined>;
    return { items: await store.listItems(auth.tenantId, query.vaultId) };
  });

  app.get('/v1/items/by-qr/:token', async (request) => {
    const auth = requireAuth(request);
    const { token } = request.params as { token: string };
    const item = await store.getItemByQrToken(auth.tenantId, token);
    if (!item) throw new NotFoundError('二维码对应的器材不存在');
    return item;
  });

  app.get('/v1/items/:id', async (request) => {
    const auth = requireAuth(request);
    const { id } = request.params as { id: string };
    const item = await store.getItem(auth.tenantId, id);
    if (!item) throw new NotFoundError('器材不存在');
    return item;
  });

  app.patch('/v1/items/:id', async (request) => {
    const auth = requireAuth(request);
    const { id } = request.params as { id: string };
    const body = request.body as Record<string, unknown>;
    const version = reqVersion(body);
    await verifyDeviceSignature(store, request, `update-item:${id}:${version}`);
    const current = await store.getItem(auth.tenantId, id);
    if (!current) throw new NotFoundError('器材不存在');

    const next: Item = {
      ...current,
      wrappedDek: typeof body.wrappedDek === 'string' ? body.wrappedDek : current.wrappedDek,
      sealedField: typeof body.sealedField === 'string' ? body.sealedField : current.sealedField,
      thumbCipher: typeof body.thumbCipher === 'string' ? body.thumbCipher : current.thumbCipher,
      photoCipher: typeof body.photoCipher === 'string' ? body.photoCipher : current.photoCipher,
      nonceCount: typeof body.nonceCount === 'number' ? body.nonceCount : current.nonceCount,
    };
    return store.putItem(next, version);
  });

  // ---- Loan ----
  app.post('/v1/loans', async (request) => {
    const auth = requireAuth(request);
    const body = request.body as Record<string, unknown>;
    const itemId = req(body, 'itemId');
    const vaultId = req(body, 'vaultId');
    const sealedRecord = req(body, 'sealedRecord');
    await verifyDeviceSignature(store, request, `create-loan:${itemId}:${sha256Hex(sealedRecord)}`);
    const item = await store.getItem(auth.tenantId, itemId);
    if (!item || item.vaultId !== vaultId) throw new NotFoundError('器材不存在');

    const loan: Loan = {
      id: newId(),
      tenantId: auth.tenantId,
      vaultId,
      itemId,
      sealedRecord,
      open: true,
      version: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    return store.createLoanWithFlag(loan);
  });

  app.get('/v1/loans', async (request) => {
    const auth = requireAuth(request);
    const query = request.query as Record<string, string | undefined>;
    if (!query.itemId) throw new BadRequestError('缺少 itemId');
    return { loans: await store.listLoansForItem(auth.tenantId, query.itemId) };
  });

  app.patch('/v1/loans/:id', async (request) => {
    const auth = requireAuth(request);
    const { id } = request.params as { id: string };
    const body = request.body as Record<string, unknown>;
    const version = reqVersion(body);
    await verifyDeviceSignature(store, request, `update-loan:${id}:${version}`);
    const current = await store.getLoan(auth.tenantId, id);
    if (!current) throw new NotFoundError('借还记录不存在');
    return store.putLoan(
      {
        ...current,
        sealedRecord: typeof body.sealedRecord === 'string' ? body.sealedRecord : current.sealedRecord,
      },
      version,
    );
  });

  app.post('/v1/loans/:id/return', async (request) => {
    const auth = requireAuth(request);
    const { id } = request.params as { id: string };
    const body = request.body as Record<string, unknown>;
    const version = reqVersion(body);
    const sealedRecord = req(body, 'sealedRecord');
    await verifyDeviceSignature(store, request, `return-loan:${id}:${version}`);
    return store.returnLoanWithFlag(auth.tenantId, id, version, sealedRecord);
  });
}
