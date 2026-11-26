import { randomUUID } from 'node:crypto';
import { ConflictError, NotFoundError } from './errors.js';
import type {
  AuditChainHead,
  AuditEvent,
  Device,
  Item,
  Loan,
  Membership,
  Session,
  Tenant,
  User,
  Vault,
} from './types.js';

/**
 * 数据访问抽象。每一条数据方法都强制携带 tenantId —— 在类型层面就不存在
 * "不带租户的查询"，这是租户隔离的第一道防线（RLS 是第三道）。
 *
 * 生产实现应按 docs/database-schema.md 落到 PostgreSQL，并保留全部不变量：
 *   - 复合键隔离
 *   - 乐观锁冲突抛 ConflictError
 *   - 审计链追加原子化且校验 expectedPrevHash
 *   - 借出/归还时 item 状态与 loan 状态同事务更新
 */
export interface Store {
  createTenant(input: Tenant): Promise<Tenant>;
  getTenant(tenantId: string): Promise<Tenant | null>;

  createUser(user: User): Promise<User>;
  getUser(tenantId: string, userId: string): Promise<User | null>;
  getUserByEmail(tenantId: string, email: string): Promise<User | null>;
  putUser(user: User): Promise<void>;
  listUsers(tenantId: string): Promise<User[]>;

  createDevice(device: Device): Promise<Device>;
  getDevice(tenantId: string, deviceId: string): Promise<Device | null>;
  listDevices(tenantId: string, userId?: string): Promise<Device[]>;
  putDevice(device: Device): Promise<void>;

  createVault(vault: Vault): Promise<Vault>;
  getVault(tenantId: string, vaultId: string): Promise<Vault | null>;
  listVaults(tenantId: string): Promise<Vault[]>;

  createMembership(membership: Membership): Promise<Membership>;
  listMembershipsForUser(tenantId: string, userId: string): Promise<Membership[]>;
  listMembershipsForVault(tenantId: string, vaultId: string): Promise<Membership[]>;
  deleteMembershipsForUser(tenantId: string, userId: string): Promise<void>;

  createItem(item: Item): Promise<Item>;
  getItem(tenantId: string, itemId: string): Promise<Item | null>;
  getItemByQrToken(tenantId: string, qrToken: string): Promise<Item | null>;
  listItems(tenantId: string, vaultId?: string): Promise<Item[]>;
  putItem(item: Item, expectedVersion: number): Promise<Item>;

  createLoanWithFlag(loan: Loan): Promise<Loan>;
  getLoan(tenantId: string, loanId: string): Promise<Loan | null>;
  listLoansForItem(tenantId: string, itemId: string): Promise<Loan[]>;
  putLoan(loan: Loan, expectedVersion: number): Promise<Loan>;
  returnLoanWithFlag(
    tenantId: string,
    loanId: string,
    expectedVersion: number,
    sealedRecord: string,
  ): Promise<{ loan: Loan; item: Item }>;

  initChainHead(tenantId: string, genesisHash: string): Promise<void>;
  getChainHead(tenantId: string): Promise<AuditChainHead | null>;
  appendAudit(input: {
    tenantId: string;
    vaultId?: string;
    sealedEvent: string;
    aad: string;
    expectedPrevHash: string;
    hash: string;
    deviceId?: string;
  }): Promise<AuditEvent>;
  listAuditEvents(tenantId: string, afterId: number, limit: number): Promise<AuditEvent[]>;

  createSession(session: Session): Promise<void>;
  getSession(tokenHash: string): Promise<Session | null>;
  revokeSession(tokenHash: string): Promise<void>;

  saveLoginState(state: {
    loginId: string;
    tenantId: string;
    email: string;
    serverLoginState: string;
    expiresAt: string;
  }): Promise<void>;
  consumeLoginState(loginId: string): Promise<{
    loginId: string;
    tenantId: string;
    email: string;
    serverLoginState: string;
  } | null>;
}

/** 极简互斥锁：按租户串行化审计链与借还状态写入。 */
class Mutex {
  private tail: Promise<void> = Promise.resolve();

  async run<T>(fn: () => Promise<T>): Promise<T> {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const previous = this.tail;
    this.tail = previous.then(() => gate);
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  }
}

function key(tenantId: string, id: string): string {
  return `${tenantId}:${id}`;
}

function now(): string {
  return new Date().toISOString();
}

/** 内存实现，仅用于测试与开发验证。不持久化，不得用于生产。 */
export class MemoryStore implements Store {
  private tenants = new Map<string, Tenant>();
  private users = new Map<string, User>();
  private emailIndex = new Map<string, string>();
  private devices = new Map<string, Device>();
  private vaults = new Map<string, Vault>();
  private memberships = new Map<string, Membership>();
  private items = new Map<string, Item>();
  private qrIndex = new Map<string, string>();
  private loans = new Map<string, Loan>();
  private chainHeads = new Map<string, AuditChainHead>();
  private auditEvents = new Map<number, AuditEvent>();
  private auditSeq = 0;
  private sessions = new Map<string, Session>();
  private loginStates = new Map<string, {
    loginId: string;
    tenantId: string;
    email: string;
    serverLoginState: string;
    expiresAt: string;
  }>();
  private locks = new Map<string, Mutex>();

  private lockFor(tenantId: string): Mutex {
    let lock = this.locks.get(tenantId);
    if (!lock) {
      lock = new Mutex();
      this.locks.set(tenantId, lock);
    }
    return lock;
  }

  async createTenant(input: Tenant): Promise<Tenant> {
    this.tenants.set(input.id, { ...input });
    await this.initChainHead(input.id, input.tkHash);
    return { ...input };
  }

  async getTenant(tenantId: string): Promise<Tenant | null> {
    return this.tenants.get(tenantId) ?? null;
  }

  async createUser(user: User): Promise<User> {
    this.users.set(key(user.tenantId, user.id), { ...user });
    this.emailIndex.set(key(user.tenantId, user.email), user.id);
    return { ...user };
  }

  async getUser(tenantId: string, userId: string): Promise<User | null> {
    return this.users.get(key(tenantId, userId)) ?? null;
  }

  async getUserByEmail(tenantId: string, email: string): Promise<User | null> {
    const id = this.emailIndex.get(key(tenantId, email));
    return id ? (this.users.get(key(tenantId, id)) ?? null) : null;
  }

  async putUser(user: User): Promise<void> {
    const existing = await this.getUser(user.tenantId, user.id);
    if (!existing) throw new NotFoundError('用户不存在');
    this.users.set(key(user.tenantId, user.id), { ...user });
    if (existing.email !== user.email) {
      this.emailIndex.delete(key(user.tenantId, existing.email));
      this.emailIndex.set(key(user.tenantId, user.email), user.id);
    }
  }

  async listUsers(tenantId: string): Promise<User[]> {
    return [...this.users.values()].filter((u) => u.tenantId === tenantId).map((u) => ({ ...u }));
  }

  async createDevice(device: Device): Promise<Device> {
    this.devices.set(key(device.tenantId, device.id), { ...device });
    return { ...device };
  }

  async getDevice(tenantId: string, deviceId: string): Promise<Device | null> {
    return this.devices.get(key(tenantId, deviceId)) ?? null;
  }

  async listDevices(tenantId: string, userId?: string): Promise<Device[]> {
    return [...this.devices.values()].filter(
      (d) => d.tenantId === tenantId && (userId === undefined || d.userId === userId),
    ).map((d) => ({ ...d }));
  }

  async putDevice(device: Device): Promise<void> {
    if (!(await this.getDevice(device.tenantId, device.id))) throw new NotFoundError('设备不存在');
    this.devices.set(key(device.tenantId, device.id), { ...device });
  }

  async createVault(vault: Vault): Promise<Vault> {
    this.vaults.set(key(vault.tenantId, vault.id), { ...vault });
    return { ...vault };
  }

  async getVault(tenantId: string, vaultId: string): Promise<Vault | null> {
    return this.vaults.get(key(tenantId, vaultId)) ?? null;
  }

  async listVaults(tenantId: string): Promise<Vault[]> {
    return [...this.vaults.values()].filter((v) => v.tenantId === tenantId).map((v) => ({ ...v }));
  }

  async createMembership(membership: Membership): Promise<Membership> {
    const id = key(membership.tenantId, `${membership.userId}:${membership.vaultId}`);
    this.memberships.set(id, { ...membership });
    return { ...membership };
  }

  async listMembershipsForUser(tenantId: string, userId: string): Promise<Membership[]> {
    return [...this.memberships.values()].filter(
      (m) => m.tenantId === tenantId && m.userId === userId,
    ).map((m) => ({ ...m }));
  }

  async listMembershipsForVault(tenantId: string, vaultId: string): Promise<Membership[]> {
    return [...this.memberships.values()].filter(
      (m) => m.tenantId === tenantId && m.vaultId === vaultId,
    ).map((m) => ({ ...m }));
  }

  async deleteMembershipsForUser(tenantId: string, userId: string): Promise<void> {
    for (const [id, m] of this.memberships) {
      if (m.tenantId === tenantId && m.userId === userId) this.memberships.delete(id);
    }
  }

  async createItem(item: Item): Promise<Item> {
    this.items.set(key(item.tenantId, item.id), { ...item });
    this.qrIndex.set(item.qrToken, key(item.tenantId, item.id));
    return { ...item };
  }

  async getItem(tenantId: string, itemId: string): Promise<Item | null> {
    return this.items.get(key(tenantId, itemId)) ?? null;
  }

  async getItemByQrToken(tenantId: string, qrToken: string): Promise<Item | null> {
    const composite = this.qrIndex.get(qrToken);
    if (!composite || !composite.startsWith(`${tenantId}:`)) return null;
    return this.items.get(composite) ?? null;
  }

  async listItems(tenantId: string, vaultId?: string): Promise<Item[]> {
    return [...this.items.values()].filter(
      (i) => i.tenantId === tenantId && (vaultId === undefined || i.vaultId === vaultId),
    ).map((i) => ({ ...i }));
  }

  async putItem(item: Item, expectedVersion: number): Promise<Item> {
    return this.lockFor(item.tenantId).run(async () => {
      const current = await this.getItem(item.tenantId, item.id);
      if (!current) throw new NotFoundError('器材不存在');
      if (current.version !== expectedVersion) throw new ConflictError();
      const next: Item = { ...item, version: expectedVersion + 1, updatedAt: now() };
      this.items.set(key(item.tenantId, item.id), next);
      return { ...next };
    });
  }

  async createLoanWithFlag(loan: Loan): Promise<Loan> {
    return this.lockFor(loan.tenantId).run(async () => {
      const item = await this.getItem(loan.tenantId, loan.itemId);
      if (!item) throw new NotFoundError('器材不存在');
      if (item.openLoanFlag === 1) throw new ConflictError('该器材已有未结借出');
      this.loans.set(key(loan.tenantId, loan.id), { ...loan });
      this.items.set(key(loan.tenantId, item.id), {
        ...item,
        openLoanFlag: 1,
        updatedAt: now(),
      });
      return { ...loan };
    });
  }

  async getLoan(tenantId: string, loanId: string): Promise<Loan | null> {
    return this.loans.get(key(tenantId, loanId)) ?? null;
  }

  async listLoansForItem(tenantId: string, itemId: string): Promise<Loan[]> {
    return [...this.loans.values()].filter(
      (l) => l.tenantId === tenantId && l.itemId === itemId,
    ).map((l) => ({ ...l }));
  }

  async putLoan(loan: Loan, expectedVersion: number): Promise<Loan> {
    return this.lockFor(loan.tenantId).run(async () => {
      const current = await this.getLoan(loan.tenantId, loan.id);
      if (!current) throw new NotFoundError('借还记录不存在');
      if (current.version !== expectedVersion) throw new ConflictError();
      const next: Loan = { ...loan, version: expectedVersion + 1, updatedAt: now() };
      this.loans.set(key(loan.tenantId, loan.id), next);
      return { ...next };
    });
  }

  async returnLoanWithFlag(
    tenantId: string,
    loanId: string,
    expectedVersion: number,
    sealedRecord: string,
  ): Promise<{ loan: Loan; item: Item }> {
    return this.lockFor(tenantId).run(async () => {
      const loan = await this.getLoan(tenantId, loanId);
      if (!loan) throw new NotFoundError('借还记录不存在');
      if (loan.version !== expectedVersion) throw new ConflictError();
      const item = await this.getItem(tenantId, loan.itemId);
      if (!item) throw new NotFoundError('器材不存在');
      const nextLoan: Loan = {
        ...loan,
        sealedRecord,
        open: false,
        version: expectedVersion + 1,
        updatedAt: now(),
      };
      const nextItem: Item = { ...item, openLoanFlag: 0, updatedAt: now() };
      this.loans.set(key(tenantId, loanId), nextLoan);
      this.items.set(key(tenantId, item.id), nextItem);
      return { loan: { ...nextLoan }, item: { ...nextItem } };
    });
  }

  async initChainHead(tenantId: string, genesisHash: string): Promise<void> {
    if (!this.chainHeads.has(tenantId)) {
      this.chainHeads.set(tenantId, { tenantId, lastEventId: 0, lastHash: genesisHash });
    }
  }

  async getChainHead(tenantId: string): Promise<AuditChainHead | null> {
    return this.chainHeads.get(tenantId) ?? null;
  }

  async appendAudit(input: {
    tenantId: string;
    vaultId?: string;
    sealedEvent: string;
    aad: string;
    expectedPrevHash: string;
    hash: string;
    deviceId?: string;
  }): Promise<AuditEvent> {
    // 与 PostgreSQL 的 SELECT ... FOR UPDATE 等价：锁住本租户链头后校验并推进。
    return this.lockFor(input.tenantId).run(async () => {
      const head = this.chainHeads.get(input.tenantId);
      if (!head) throw new NotFoundError('租户审计链不存在');
      if (input.expectedPrevHash !== head.lastHash) {
        throw new ConflictError('审计链前序哈希不匹配，请重算后重试');
      }
      const event: AuditEvent = {
        id: ++this.auditSeq,
        tenantId: input.tenantId,
        ...(input.vaultId ? { vaultId: input.vaultId } : {}),
        sealedEvent: input.sealedEvent,
        aad: input.aad,
        prevHash: head.lastHash,
        hash: input.hash,
        ...(input.deviceId ? { deviceId: input.deviceId } : {}),
        createdAt: now(),
      };
      this.auditEvents.set(event.id, event);
      this.chainHeads.set(input.tenantId, {
        ...head,
        lastEventId: event.id,
        lastHash: event.hash,
      });
      return { ...event };
    });
  }

  async listAuditEvents(tenantId: string, afterId: number, limit: number): Promise<AuditEvent[]> {
    return [...this.auditEvents.values()]
      .filter((e) => e.tenantId === tenantId && e.id > afterId)
      .sort((a, b) => a.id - b.id)
      .slice(0, limit)
      .map((e) => ({ ...e }));
  }

  async createSession(session: Session): Promise<void> {
    this.sessions.set(session.tokenHash, { ...session });
  }

  async getSession(tokenHash: string): Promise<Session | null> {
    return this.sessions.get(tokenHash) ?? null;
  }

  async revokeSession(tokenHash: string): Promise<void> {
    const session = this.sessions.get(tokenHash);
    if (session) this.sessions.set(tokenHash, { ...session, revokedAt: now() });
  }

  async saveLoginState(state: {
    loginId: string;
    tenantId: string;
    email: string;
    serverLoginState: string;
    expiresAt: string;
  }): Promise<void> {
    this.loginStates.set(state.loginId, { ...state });
  }

  async consumeLoginState(loginId: string): Promise<{
    loginId: string;
    tenantId: string;
    email: string;
    serverLoginState: string;
  } | null> {
    const state = this.loginStates.get(loginId);
    if (!state) return null;
    if (new Date(state.expiresAt).getTime() < Date.now()) {
      this.loginStates.delete(loginId);
      return null;
    }
    this.loginStates.delete(loginId);
    const { loginId: id, tenantId, email, serverLoginState } = state;
    return { loginId: id, tenantId, email, serverLoginState };
  }
}

export function newId(): string {
  return randomUUID();
}
