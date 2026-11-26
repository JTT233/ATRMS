# 器材借还管理系统｜密文数据库表结构 v0.1

> Phase 1 交付物 · 日期 2026-11-24
> 对应迁移脚本：`apps/api/migrations/0001_init.sql`（PostgreSQL 14+）

---

## 0. 设计原则与一处重要修正

### 0.1 四条硬原则

1. **服务端只存密文字节与随机标识。** 名称、型号、序列号、位置、借用人、照片、审计内容全部是 `bytea` 密文信封。
2. **租户隔离做三层**：应用 `Store` 每个方法强制携带 `tenantId`（第一道）→ 复合外键 `(tenant_id, vault_id)`（第二道）→ PostgreSQL RLS（第三道）。
3. **最小元数据**：不存 IP、不存 User-Agent、不存业务状态明文；ID 全部随机 UUID，二维码是 128-bit opaque token。
4. **不信任客户端提交的顺序**：审计链由数据库行锁 + 事务裁定，客户端只能提交"我期望的前序哈希"。

### 0.2 对蓝图的修正：`wrapped_TK` → `tk_hash`

蓝图 ER 图中 `TENANT.wrapped_TK` 的表述在密码学上不成立：**TK 是密钥层级的根，不存在更高层密钥可以包裹它**。若服务端保存一份"被包裹的 TK"，就等于持有可重构的材料，与零知识目标冲突。

本实现改为：

- 服务端只存 `tk_hash = SHA-256(TK)`（32 字节）作为**恢复分片重构正确性的校验锚点**；
- TK 明文只存在于组织管理员设备内存中，3 份 Shamir 分片只在管理员各自的离线介质上；
- 平台获得 `tk_hash` 与所有 wrapped blob，仍无法反推 TK——因为没有任何一份分片在服务端。

`combineTenantKey()` 在重构后会用 `H(TK)` 与该锚点比对，不匹配即拒绝（分片库本身不校验重构结果，这一步不可省）。

---

## 1. 表清单与密文边界

| 表 | 明文列（平台可见） | 密文列（平台不可读） | 说明 |
|---|---|---|---|
| `tenants` | id、阈值、计费状态、时间戳 | — | `tk_hash` 是校验锚点，不是密钥 |
| `users` | id、tenant_id、email、active、时间戳 | `opaque_record`、`wrapped_uk`、`kek_wrapped_uk`、`role_cipher` | UK 有两份包裹副本，见 §3 |
| `devices` | id、公钥、批准状态、时间戳 | `label_cipher` | 私钥在浏览器 non-extractable |
| `vaults` | id、tenant_id、parent_id、时间戳 | `wrapped_vk`、`label_cipher` | 成员用的是 memberships 里的副本 |
| `memberships` | 三个 ID、时间戳 | `wrapped_vk_for_user`、`role_cipher` | 每成员一份 VK 副本 |
| `items` | id、tenant_id、vault_id、qr_token、version、nonce_count、时间戳、`open_loan_flag` | `wrapped_dek`、`sealed_field`、`thumb_cipher`、`photo_cipher` | 见 §2 关于 `open_loan_flag` |
| `loans` | id、三个 ID、open、version、时间戳 | `sealed_record` | 借用人、期限、状态照片全在密文里 |
| `audit_events` | id、tenant/vault/device ID、aad、prev_hash、hash、时间戳 | `sealed_event` | 链结构本身公开，内容加密 |
| `audit_chain_heads` | tenant_id、last_event_id、last_hash | — | 顺序一致性的裁定点 |
| `sessions` | tenant/user ID、时间戳 | — | 只存 `token_hash`，不存明文 token |
| `login_states` | login_id、tenant_id、email、时间戳 | `server_login_state` | OPAQUE 临时状态，短 TTL |
| `invitations` | tenant_id、email、时间戳 | `token_hash`、`role_cipher` | 一次性邀请 |

### 1.1 关于 `items.open_loan_flag`

这是一个**有意的、最小化的元数据权衡**：平台只知道"这件器材当前有无活跃借出"，不知道借给谁、什么时候借的、借去做什么。客户端不信任该字段作为业务真值——真实状态在 `sealed_field` / `loans.sealed_record` 里，由客户端解密后计算。

如果试点客户连这一位元信息都不能接受，可把它固定为 0、完全依赖客户端密文状态，代价是服务端无法做借出冲突的粗粒度拦截。这是一个可配置项，不是协议常量。

---

## 2. 租户隔离的三层实现

### 第一层：应用 Store（强制）

`Store` 所有数据方法的签名都带 `tenantId`，内存实现用 `${tenantId}:${id}` 复合键。**在类型层面就没有"不带租户的查询"**，这是最重要的一层——绝大多数越权来自应用逻辑遗漏。

### 第二层：复合外键（结构约束）

`items`、`loans`、`memberships` 的外键都是 `(tenant_id, referenced_id)` 复合形式，并引用目标表的 `(tenant_id, id)` 唯一约束。数据库层面阻止"A 租户的器材挂到 B 租户的 Vault"。

### 第三层：RLS（纵深防御）

十张业务表全部开启行级安全：

```sql
CREATE POLICY tenant_isolation ON items
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
```

应用每次取连接后必须执行 `SET LOCAL app.tenant_id = '<uuid>'`（事务内 LOCAL，避免连接复用串号）。未设置时 `current_setting(..., true)` 返回 NULL，比较结果为 NULL，**所有行都不可见**——即"忘记设置"是安全失败，不会退化成跨租户读取。

`tenants` 表本身不设 RLS：认证阶段需要按 email 定位租户。部署时应用账号只应拥有该表 `SELECT(id, billing_status)` 的最小权限。

---

## 3. 密钥包裹副本分布

理解"谁持有什么"是审计这个设计的关键：

```
TK ──┬─ wrap ─> users.wrapped_uk          （组织恢复副本，管理员用 TK 解）
     ├─ wrap ─> vaults.wrapped_vk          （VK 主副本）
     └─ wrap ─> AK（存于审计配置表/信封，本迁移中以 tenant 配置形式预留）

UK ──┬─ KEK(OPAQUE export_key) wrap ─> users.kek_wrapped_uk  （本人登录解包）
     └─ ...                                                  

UK ── wrap ─> memberships.wrapped_vk_for_user                 （成员进 Vault）

VK ── wrap ─> items.wrapped_dek                               （器材 DEK）

DEK ── AES-GCM ─> items.sealed_field / thumb_cipher / photo_cipher
                  loans.sealed_record
```

关键点：**没有任何一行同时包含某把密钥及其解包材料**。平台拿到整库，也只能看到一堆互不匹配的密文信封。

---

## 4. 审计链的顺序一致性协议

这是外部评审清单第 5 项，实现必须严格照此执行：

```sql
BEGIN;
  -- 1. 锁链头（串行化本租户的审计写入）
  SELECT last_event_id, last_hash
    FROM audit_chain_heads
   WHERE tenant_id = $1
   FOR UPDATE;

  -- 2. 校验客户端提交的 expectedPrevHash == last_hash
  --    不匹配则 ROLLBACK 并返回 409，要求客户端基于最新状态重算哈希后重试

  -- 3. 计算 new_hash = H(last_hash ‖ len(aad) ‖ aad ‖ ct ‖ tag ‖ ts)
  --    其中 ct/tag 来自 sealed_event，ts 由服务端生成

  -- 4. 插入事件（id 由 IDENTITY 分配，保证单调递增）
  INSERT INTO audit_events
    (tenant_id, vault_id, sealed_event, aad, prev_hash, hash, device_id)
  VALUES (...);

  -- 5. 推进链头
  UPDATE audit_chain_heads
     SET last_event_id = <new id>, last_hash = <new_hash>
   WHERE tenant_id = $1;
COMMIT;
```

**为什么需要行锁：** 若不加锁，两个并发请求可能读到同一个 `last_hash`，写出两条 `prev_hash` 相同、互相分叉的"链"。客户端验证时会检测到分叉并报警——但那是事后发现。行锁让分叉在数据写入前就被阻止。

**创世值：** 新租户创建时 `last_hash = SHA-256("genesis:v1:" || tenant_id)`，客户端验证器从同一公式开始重算。

**外部锚定（Phase 3）：** 每日根哈希通过独立通道（邮件 / 第三方透明日志）发给组织，防止平台整段回滚后重算链——哈希链只能防篡改，不能防"连历史一起换掉"。

---

## 5. 乐观锁与冲突处理

`items.version` / `loans.version` 用于乐观锁：

- 客户端上传更新时必须带它解密时看到的 `version`；
- 服务端执行 `UPDATE ... WHERE tenant_id = $1 AND id = $2 AND version = $3`；
- 影响行数为 0 → 返回 `409 CONFLICT`，客户端拉取最新版本、重试业务逻辑（例如重新判断器材是否仍可借出）；
- 成功后 `version = version + 1`，由触发器维护 `updated_at`。

**离线场景：** 断网期间的借出操作在本地排队，联网后按上述协议逐条提交；冲突必须由客户端基于解密后的最新状态重新决策，不能静默覆盖。这是蓝图 §12「离线与同步」验收项的数据层基础。

---

## 6. GCM nonce 预算

`items.nonce_count` 记录该器材 DEK 已加密的次数。AES-GCM 在随机 96-bit IV 下，同一密钥安全上限约 2^32 次。客户端每次加密递增该计数，达到阈值（建议提前到 2^31）前必须触发 DEK 轮换：

1. 生成新 `DEK'`；
2. 用当前 `VK` 包裹 `DEK'`，写入 `wrapped_dek`；
3. 用 `DEK'` 重新加密全部字段与照片，AAD 中的 `version` 递增；
4. `nonce_count` 归零；
5. 写审计事件。

轮换过程需分批 + 可恢复，避免大照片集阻塞 UI。

---

## 7. 生命周期与清理

| 数据 | 保留期 | 清理方式 |
|---|---|---|
| `sessions` | 过期后 7 天 | 定时 `DELETE` |
| `login_states` | 过期后 1 天 | 定时 `DELETE` |
| `invitations` | 过期后 30 天 | 定时 `DELETE` |
| `audit_events` | 合同期 + 法定期限 | **不自动删除**；删除会影响链完整性 |
| 审计事件中的照片 | 同审计保留期 | 密文对象存储生命周期策略 |

迁移脚本末尾给出了清理 SQL 注释，接入定时任务时取消注释即可。

---

## 8. 部署注意事项

- 应用连接角色**不应有 DDL 权限**，迁移由独立角色执行；
- `app.tenant_id` 必须在事务内用 `SET LOCAL` 设置，禁止跨请求复用；
- 连接字符串强制 TLS；对象存储桶的服务端加密只保护元数据层，**不用于业务内容**；
- 备份密文库时，`tk_hash` 与 wrapped blob 一起备份才有恢复意义，但备份本身不含任何分片；
- RLS 策略与复合外键都需要覆盖测试：用 A 租户会话尝试读 B 租户 `items`，必须返回 0 行。

---

## 9. 待评审确认

1. `tk_hash` 用 `SHA-256` 是否足够（考虑 TK 是 256-bit 随机值，无离线字典攻击面）；
2. `open_loan_flag` 这一位元数据是否接受，还是完全移除；
3. RLS 策略是否需要在 `tenants` 上也加一层（认证流程的例外如何处理）；
4. 审计链行锁在高并发下的吞吐是否可接受，是否需要按 Vault 分片链；
5. `nonce_count` 由客户端上报是否可信——是否应改为服务端按写入次数独立计数作为第二道防线。
