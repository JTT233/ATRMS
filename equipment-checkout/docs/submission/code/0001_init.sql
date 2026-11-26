-- ============================================================
-- 器材借还管理系统 · 初始密文表结构
-- 版本: 0001_init
-- 日期: 2026-11-24
-- 目标: PostgreSQL 14+
--
-- 设计原则:
--   1. 服务端只存密文字节与随机标识，不存任何明文业务字段。
--   2. 租户隔离做三层: 应用 Store 强制 tenant_id + 复合外键 + RLS。
--   3. 不存 IP、不存用户代理、不存可作为业务内容的明文状态。
--   4. 审计链顺序一致性由 audit_chain_heads 行锁 + 事务保证。
--
-- 重要修正: 蓝图 ER 图中的 TENANT.wrapped_TK 在本实现中改为 tk_hash。
--   原因: TK 是密钥层级的根，没有更高层密钥可以包裹它；服务端连包裹
--   副本都不应持有，只保存 SHA-256(TK) 作为恢复分片的校验锚点。
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ------------------------------------------------------------
-- 租户
-- ------------------------------------------------------------
CREATE TABLE tenants (
  id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  -- SHA-256(TK)，32 字节。仅用于校验 2-of-3 分片重构结果是否正确。
  -- 平台拿到它也无法反推 TK，且分片不在服务端，故无重构材料。
  tk_hash               bytea       NOT NULL CHECK (octet_length(tk_hash) = 32),
  recovery_threshold    smallint    NOT NULL DEFAULT 2 CHECK (recovery_threshold = 2),
  recovery_share_count  smallint    NOT NULL DEFAULT 3 CHECK (recovery_share_count = 3),
  -- 计费状态是平台自身元数据，与客户业务数据无关。
  billing_status        text        NOT NULL DEFAULT 'trial',
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN tenants.tk_hash IS
  'SHA-256(TK) 校验锚点。服务端不存 TK 明文或可解包副本；恢复分片仅存于组织管理员离线介质。';

-- ------------------------------------------------------------
-- 用户（OPAQUE 凭据 + 两份 UK 包裹副本）
-- ------------------------------------------------------------
CREATE TABLE users (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  -- 邮箱仅用于认证与邀请，是平台可见的元数据；不参与任何业务内容。
  email             text        NOT NULL,
  -- OPAQUE credential record。服务端无口令等价物。
  opaque_record     bytea,
  -- UK 的组织恢复副本：用 TK 包裹。管理员可解开以重置成员口令。
  wrapped_uk        bytea,
  -- UK 的登录副本：用 KEK 包裹，KEK = HKDF(OPAQUE export_key, salt, "kek-v1")。
  kek_wrapped_uk    bytea,
  -- HKDF salt，16 字节随机。公开也无害。
  kek_salt          bytea       CHECK (kek_salt IS NULL OR octet_length(kek_salt) = 16),
  -- 加密的角色与 Vault 权限摘要（供客户端解密后做 RBAC 判定）。
  role_cipher       bytea,
  active            boolean     NOT NULL DEFAULT true,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, email)
);

COMMENT ON COLUMN users.wrapped_uk IS '用 TK 包裹的 UK，仅组织管理员在恢复流程中经客户端解开。';
COMMENT ON COLUMN users.kek_wrapped_uk IS '用 OPAQUE export_key 派生的 KEK 包裹的 UK，用户登录时解包。';
COMMENT ON COLUMN users.opaque_record IS 'OPAQUE credential record，不含口令或口令等价物。';

-- ------------------------------------------------------------
-- 设备（Ed25519 公钥登记）
-- ------------------------------------------------------------
CREATE TABLE devices (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- Ed25519 公钥原始字节，32 字节。私钥在浏览器生成且 non-extractable。
  public_key   bytea       NOT NULL CHECK (octet_length(public_key) = 32),
  label_cipher bytea,
  approved     boolean     NOT NULL DEFAULT false,
  approved_by  uuid        REFERENCES users(id),
  last_seen    timestamptz,
  revoked_at   timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, public_key)
);

-- ------------------------------------------------------------
-- 保险库
-- ------------------------------------------------------------
CREATE TABLE vaults (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  -- 用 TK 包裹的 VK。成员实际使用的是用各自 UK 包裹的副本（见 memberships）。
  wrapped_vk  bytea       NOT NULL,
  label_cipher bytea,
  parent_id   uuid        REFERENCES vaults(id),
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------
-- 成员-保险库授权（每成员一份用其 UK 包裹的 VK）
-- ------------------------------------------------------------
CREATE TABLE memberships (
  tenant_id          uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id            uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  vault_id           uuid        NOT NULL,
  -- 用该成员 UK 包裹的 VK；成员登录后用 UK 解出 VK。
  wrapped_vk_for_user bytea      NOT NULL,
  -- 该 Vault 内的角色（加密），客户端解密后执行 RBAC。
  role_cipher        bytea,
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id, vault_id),
  FOREIGN KEY (tenant_id, vault_id) REFERENCES vaults(tenant_id, id) ON DELETE CASCADE
);

-- ------------------------------------------------------------
-- 器材
-- ------------------------------------------------------------
CREATE TABLE items (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  vault_id        uuid        NOT NULL,
  -- 用 VK 包裹的 DEK。
  wrapped_dek     bytea       NOT NULL,
  -- 名称/型号/序列号/位置/备注 的 AES-256-GCM 密文信封（含 iv/ct/tag/aad）。
  sealed_field    bytea       NOT NULL,
  thumb_cipher    bytea,
  photo_cipher    bytea,
  -- 128-bit 随机 opaque token，扫码接口只用它映射到记录 ID。
  qr_token        bytea       NOT NULL CHECK (octet_length(qr_token) = 16),
  -- 不透明借出标记: 0=无活跃借出, 1=有活跃借出。语义由客户端定义，
  -- 平台只知道"是否有借出"，不知道借给谁、借了什么。
  open_loan_flag  smallint    NOT NULL DEFAULT 0 CHECK (open_loan_flag IN (0, 1)),
  version         integer     NOT NULL DEFAULT 1 CHECK (version > 0),
  -- 同一 DEK 的 GCM 加密次数，达到 2^32 前强制轮换。
  nonce_count     bigint      NOT NULL DEFAULT 0 CHECK (nonce_count >= 0),
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (qr_token),
  FOREIGN KEY (tenant_id, vault_id) REFERENCES vaults(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX items_vault_updated_idx ON items (tenant_id, vault_id, updated_at DESC);
CREATE INDEX items_tenant_qr_idx     ON items (tenant_id, qr_token);

COMMENT ON COLUMN items.open_loan_flag IS
  '有意保留的最小元数据：平台仅知有无活跃借出，不知借用人/物品内容。客户端不信任此字段作为真实状态。';

-- ------------------------------------------------------------
-- 借还记录
-- ------------------------------------------------------------
CREATE TABLE loans (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  vault_id     uuid        NOT NULL,
  item_id      uuid        NOT NULL,
  -- 借用人/借出时间/归还期限/状态照片 的密文信封。
  sealed_record bytea      NOT NULL,
  -- 是否有未结借出（同步提示用，语义不透明）。
  open         boolean     NOT NULL DEFAULT true,
  version      integer     NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, vault_id) REFERENCES vaults(tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, item_id)  REFERENCES items(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX loans_item_open_idx ON loans (tenant_id, item_id, open);
CREATE INDEX loans_vault_idx     ON loans (tenant_id, vault_id, created_at DESC);

-- ------------------------------------------------------------
-- 审计事件 + 链头（顺序一致性）
-- ------------------------------------------------------------
CREATE TABLE audit_chain_heads (
  tenant_id     uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  last_event_id bigint      NOT NULL DEFAULT 0,
  -- 创世值 = SHA-256("genesis:v1:" || tenant_id::text)。
  last_hash     bytea       NOT NULL CHECK (octet_length(last_hash) = 32),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
  id           bigint      GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  vault_id     uuid,
  -- AK 加密的事件内容信封（含 iv/ct/tag/aad）。
  sealed_event bytea       NOT NULL,
  -- 参与哈希计算的上下文（tenant/vault/type/objectId/version），非业务内容。
  aad          text        NOT NULL,
  prev_hash    bytea       NOT NULL CHECK (octet_length(prev_hash) = 32),
  hash         bytea       NOT NULL CHECK (octet_length(hash) = 32),
  device_id    uuid        REFERENCES devices(id),
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_tenant_seq_idx ON audit_events (tenant_id, id);

COMMENT ON TABLE audit_chain_heads IS
  '每租户一行。写入审计事件前必须 SELECT ... FOR UPDATE 锁此行，校验客户端提交的 expectedPrevHash 与 last_hash 一致，再插入事件并更新链头，全程单事务。';

-- ------------------------------------------------------------
-- 会话（只存 token 哈希）
-- ------------------------------------------------------------
CREATE TABLE sessions (
  token_hash bytea       PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);

CREATE INDEX sessions_expiry_idx ON sessions (expires_at);

COMMENT ON COLUMN sessions.token_hash IS 'SHA-256(session token)。数据库泄露也无法直接冒用会话。';

-- ------------------------------------------------------------
-- OPAQUE 登录临时状态
-- ------------------------------------------------------------
CREATE TABLE login_states (
  login_id           uuid        PRIMARY KEY,
  tenant_id          uuid,
  email              text        NOT NULL,
  server_login_state bytea       NOT NULL,
  expires_at         timestamptz NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX login_states_expiry_idx ON login_states (expires_at);

-- ------------------------------------------------------------
-- 邀请令牌（只存哈希）
-- ------------------------------------------------------------
CREATE TABLE invitations (
  token_hash bytea       PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email      text,
  role_cipher bytea,
  invited_by uuid        REFERENCES users(id),
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------
-- 自动维护 updated_at
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tenants_updated_at BEFORE UPDATE ON tenants
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER items_updated_at BEFORE UPDATE ON items
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER loans_updated_at BEFORE UPDATE ON loans
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ------------------------------------------------------------
-- 行级安全（纵深防御；应用层的 tenant_id 强制仍是第一道防线）
-- ------------------------------------------------------------
-- 应用连接角色必须设置 SET LOCAL app.tenant_id = '<uuid>'。
-- current_setting(..., true) 未设置时返回 NULL，比较为 NULL → 拒绝全部行，
-- 因此"忘记设置"是安全失败，不会导致跨租户读取。

ALTER TABLE users         ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices       ENABLE ROW LEVEL SECURITY;
ALTER TABLE vaults        ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships   ENABLE ROW LEVEL SECURITY;
ALTER TABLE items         ENABLE ROW LEVEL SECURITY;
ALTER TABLE loans         ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events  ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions      ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations   ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'users','devices','vaults','memberships','items','loans',
    'audit_events','audit_chain_heads','sessions','invitations'
  ] LOOP
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)::uuid) '
      || 'WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true)::uuid)',
      t
    );
  END LOOP;
END;
$$;

-- tenants 表本身不设 RLS：认证流程需要按 email 定位租户。
-- 但应用账号只应拥有 SELECT(Id, billing_status) 的最小权限，此项在部署清单中落实。

-- ------------------------------------------------------------
-- 运维用清理（建议由定时任务执行）
-- ------------------------------------------------------------
-- DELETE FROM sessions      WHERE expires_at < now() - interval '7 days';
-- DELETE FROM login_states  WHERE expires_at < now() - interval '1 day';
-- DELETE FROM invitations   WHERE expires_at < now() - interval '30 days';

-- ============================================================
-- 迁移结束
-- ============================================================
