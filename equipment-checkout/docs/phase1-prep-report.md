# Phase 1 准备工作报告 v0.1

> 日期：2026-11-24
> 范围：密文数据库表结构 + 正式 API 骨架 + 送审材料包
> 结论：三项准备工作完成，测试与构建全绿；**外部密码学评审仍是进入 Phase 1 完整开发的硬门槛**。

---

## 1. 本轮交付

### 1.1 密文数据库表结构

| 产物 | 路径 |
|---|---|
| PostgreSQL 迁移脚本 | `apps/api/migrations/0001_init.sql` |
| 设计说明 | `docs/database-schema.md` |

覆盖 12 张表：`tenants`、`users`、`devices`、`vaults`、`memberships`、`items`、`loans`、`audit_events`、`audit_chain_heads`、`sessions`、`login_states`、`invitations`。

**关键设计决策：**

- 修正蓝图 ER 图中的 `TENANT.wrapped_TK`：TK 是密钥层级的根，没有更高层密钥可包裹它。服务端改为只存 `tk_hash = SHA-256(TK)` 作为 2-of-3 分片重构的校验锚点，**不持有任何形式的 TK 副本**。
- 三层租户隔离：应用 Store 强制 `tenantId` → 复合外键 `(tenant_id, referenced_id)` → PostgreSQL RLS（`SET LOCAL app.tenant_id`）。
- UK 存两份包裹副本：`kek_wrapped_uk`（本人从 OPAQUE `export_key` 派生 KEK 解包）与 `wrapped_uk`（管理员用 TK 解包，用于口令重置）。
- 审计链用 `audit_chain_heads` 行锁 + 事务串行化写入，客户端提交 `expectedPrevHash`，不匹配返回 409。
- `items.open_loan_flag` 是有意保留的最小元数据：平台仅知有无活跃借出，不知借给谁、借了什么。

### 1.2 正式 API 骨架

从内存验证骨架演进为分层架构：

```
apps/api/src/
├── config.ts               配置
├── types.ts                领域类型（所有密文字段为 hex 字符串）
├── errors.ts               错误分级 + 统一错误处理（不回显内部细节）
├── server-crypto.ts        仅哈希与随机令牌；不接触任何业务密钥
├── store.ts                Store 接口 + MemoryStore（强制 tenantId、乐观锁、原子追加）
├── plugins/
│   ├── auth.ts             Bearer 会话认证（token 只存哈希）
│   ├── rate-limit.ts       固定窗口限流（IP 仅内存、不落库）
│   └── device-signature.ts Ed25519 已批准设备签名校验
└── routes/
    ├── auth.ts             OPAQUE 注册/登录 + 会话签发
    ├── cipher.ts           Vault / Item / Loan 密文 CRUD
    ├── audit.ts            审计链追加与读取
    └── devices.ts          设备登记、批准、吊销
```

**服务端保持"哑"：** 只做认证、签名校验、租户归属校验、版本/状态原子更新、密文字节存取。不解析任何业务内容，不持有 TK/UK/VK/DEK/AK。

**新落地的安全控制：**

- 会话 token 只以 `SHA-256(token)` 存储；
- 速率限制按 IP + 路径在内存中计数（认证 10 次/分钟、扫码 120 次/分钟、默认 300 次/分钟），不持久化 IP；
- 所有密文写操作必须由已批准且未吊销的设备用 Ed25519 签名，签名 Payload 由路由显式构造，不依赖 JSON 键顺序；
- 借出/归还时 `loan.open` 与 `items.open_loan_flag` 同锁更新；
- 乐观锁：`version` 不匹配返回 409。

### 1.3 送审材料包

`docs/review/`：

- `README.md` — 评审目标、输入清单、范围边界、交付期望、准入判据；
- `test-vectors.md` — 创世哈希、AAD、审计链哈希的真实计算向量（可独立复现）；
- `review-questions.md` — 16 个需评审者明确回答的问题，含设备签名防重放、VK 轮换原子性、nonce 计数可信度、Web 代码下发风险等。

---

## 2. 验证结果

| 命令 | 结果 |
|---|---|
| `npm test` | **23 项全部通过**（API 8 项 + 加密核心 15 项） |
| `npm run build` | **三个工作区全部通过** |

新增的 API 测试覆盖：

1. OPAQUE 真实注册/登录往返 + 错误口令拒绝；
2. 无 token 访问受保护路由返回 401；
3. 租户隔离：A 会话按 ID 和按二维码读取 B 的器材均返回 404；
4. 设备签名：缺签名 401、错签名 403；
5. 乐观锁：更新成功后版本递增，旧版本重试返回 409；
6. 借还原子性：借出后置标志位、重复借出 409、归还后清零；
7. 审计链：链接正确、陈旧前序哈希 409；
8. 跨实现一致性：服务端 `computeAuditHash` 与加密核心 `auditHash` 逐字节相同；
9. 限流：超过窗口上限返回 429。

---

## 3. 仍未解决 / 需外部确认

1. **外部密码学评审未开始** — 这是 Phase 1 完整开发的硬门槛，材料包已就绪。
2. **PostgreSQL 实现未编写** — 当前是可注入的 `MemoryStore`；生产需实现 `PostgresStore`，落实 RLS 会话变量、事务与行锁。迁移脚本已写好。
3. **设备签名 Payload 无防重放** — 当前不含时间戳/nonce，已列为评审问题 Q7，需评审后决定是否加一次性挑战。
4. **未接对象存储** — 照片密文字段目前是 hex 字符串存在数据库，Phase 1 需改为 S3 兼容对象存储引用。
5. **OPAQUE `serverSetup` 未持久化** — 仍可用环境变量注入，但未接数据库/密钥管理。
6. **邀请流程未实现** — 当前注册可直接传 `tenantId`，生产必须由一次性邀请令牌授权（已在路由注释标注）。
7. **前端仍是技术验证台** — 未接入新 API；包体积 1.13 MB（gzip 357 KB）的超限警告仍在。
8. **真机扫码与浏览器矩阵未测**。

---

## 4. 建议的下一步顺序

1. 固定代码版本，把 `docs/review/` 送外部密码学评审；
2. 评审期间并行做低风险工作：实现 `PostgresStore`、接对象存储、补邀请流程；
3. 评审结论回来后，按问题清单修改协议与实现，再进入 Phase 1 完整开发；
4. 同步启动浏览器矩阵与真机扫码冒烟测试。

---

## 5. 门槛清单更新

| 门槛 | 状态 |
|---|---|
| 外部密码学评审通过，无高危缺陷 | ❌ 材料就绪，待送审 |
| 确定数据库与对象存储的密文表结构 | ✅ 已完成（对象存储引用待 Phase 1） |
| 确定试点客户与 3 名分片管理员 | ❌ 待用户推进 |
| 落实境内云账号、TLS、WAF 与日志策略 | ❌ 待用户推进 |
| 完成浏览器矩阵与真机扫码冒烟测试 | ❌ 待 Phase 1 |
