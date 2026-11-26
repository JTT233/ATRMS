// 领域类型。所有 *Cipher / *Sealed / wrapped* / *Record / *Hash 字段均为
// 十六进制字符串形式的密文或不透明字节；服务端没有能力解释其中内容。

export interface Tenant {
  id: string;
  tkHash: string;
  recoveryThreshold: number;
  recoveryShareCount: number;
  billingStatus: string;
  createdAt: string;
}

export interface CreateTenantInput {
  id?: string;
  tkHash: string;
  billingStatus?: string;
}

export interface User {
  id: string;
  tenantId: string;
  email: string;
  opaqueRecord?: string;
  wrappedUk?: string;
  kekWrappedUk?: string;
  kekSalt?: string;
  roleCipher?: string;
  active: boolean;
  createdAt: string;
}

export interface Device {
  id: string;
  tenantId: string;
  userId: string;
  publicKey: string;
  labelCipher?: string;
  approved: boolean;
  approvedBy?: string;
  revokedAt?: string;
  createdAt: string;
}

export interface Vault {
  id: string;
  tenantId: string;
  wrappedVk: string;
  labelCipher?: string;
  parentId?: string;
  createdAt: string;
}

export interface Membership {
  tenantId: string;
  userId: string;
  vaultId: string;
  wrappedVkForUser: string;
  roleCipher?: string;
  createdAt: string;
}

export interface Item {
  id: string;
  tenantId: string;
  vaultId: string;
  wrappedDek: string;
  sealedField: string;
  thumbCipher?: string;
  photoCipher?: string;
  qrToken: string;
  openLoanFlag: 0 | 1;
  version: number;
  nonceCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface Loan {
  id: string;
  tenantId: string;
  vaultId: string;
  itemId: string;
  sealedRecord: string;
  open: boolean;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface AuditChainHead {
  tenantId: string;
  lastEventId: number;
  lastHash: string;
}

export interface AuditEvent {
  id: number;
  tenantId: string;
  vaultId?: string;
  sealedEvent: string;
  aad: string;
  prevHash: string;
  hash: string;
  deviceId?: string;
  createdAt: string;
}

export interface Session {
  tokenHash: string;
  tenantId: string;
  userId: string;
  expiresAt: string;
  revokedAt?: string;
}

export interface AuthContext {
  tenantId: string;
  userId: string;
  tokenHash: string;
}
