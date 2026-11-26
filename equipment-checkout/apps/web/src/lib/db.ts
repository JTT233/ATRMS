import Dexie, { type EntityTable } from 'dexie';

export interface CachedEnvelope {
  id: string;
  tenantId: string;
  vaultId: string;
  type: string;
  version: number;
  sealed: unknown;
  updatedAt: number;
}

class VaultDatabase extends Dexie {
  envelopes!: EntityTable<CachedEnvelope, 'id'>;

  constructor() {
    super('equipment-vault');
    this.version(1).stores({
      envelopes: 'id, tenantId, vaultId, type, updatedAt',
    });
  }
}

export const db = new VaultDatabase();
