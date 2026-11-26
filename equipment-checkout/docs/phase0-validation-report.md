# Phase 0 技术验证报告 v0.1

> 日期：2026-11-24
> 部署路线：多租户 SaaS + 预留自托管
> 结论：**关键技术风险已通过验证，可进入 Phase 1 开发；密码学协议仍需外部评审。**
> 后续进展：密文表结构、正式 API 骨架与送审材料包已完成，见 `phase1-prep-report.md`。

---

## 1. 已执行命令与结果

| 命令 | 结果 |
|---|---|
| `npm test` | 通过。加密核心 15 项 + OPAQUE 认证往返 1 项，共 16 项全部通过 |
| `npm run build` | 通过。api / web / crypto 三个工作区均构建成功 |

**环境：** Node v22.22.2，npm 10.9.7，TypeScript 5.9.3，Vite 8.3.8，Vitest 5.1.1。

---

## 2. 验证覆盖点

### 2.1 加密核心（`packages/crypto`）

- AES-256-GCM 加解密往返、随机 IV、16 字节 tag；
- AAD 上下文绑定：跨租户（tenantId 不同）密文拒绝解密；
- 密文篡改触发 GCM 校验失败；
- 不同密钥加密同一明文得到不同密文；
- KEK 包裹/解包 DEK，且 purpose 不匹配时拒绝；
- HKDF 确定性与用途隔离；
- OPAQUE sessionKey 派生 KEK；
- Argon2id（64 MiB / t=3 / p=4）派生确定；
- Shamir 2-of-3：任意两份可恢复，单份失败，错误哈希校验失败；
- 审计哈希链：篡改密文后重算哈希不一致。

### 2.2 OPAQUE 认证（`apps/api`）

- 使用 `@serenity-kit/opaque` 1.1.0；
- 完整注册 → 登录往返通过；
- 正确口令得到 sessionKey，错误口令客户端校验失败；
- 服务端只保存 registration record，不接触口令。

### 2.3 PWA 与扫码（`apps/web`）

- Vite PWA 生成 `manifest.webmanifest`、`sw.js`、预缓存 5 个文件；
- 响应式页面构建通过；
- 扫码层实现原生 `BarcodeDetector` 优先、`@zxing/browser` 回退（真机扫描待 Phase 1 验证）。

---

## 3. 关键依赖选型

| 组件 | 版本 | 选型理由 |
|---|---|---|
| OPAQUE | `@serenity-kit/opaque` 1.1.0 | 基于 opaque-ke，有 7ASecurity 渗透测试与白盒审查报告 |
| Shamir | `shamir-secret-sharing` 0.0.4 | Cure53 与 Zellic 独立审计，零依赖，支持浏览器 |
| Argon2id | `hash-wasm` 4.13.0 | 浏览器可用的 wasm 实现 |
| 内容加密 | WebCrypto 原生 AES-GCM / HKDF / Ed25519 | 无第三方加密实现依赖 |
| 本地缓存 | Dexie 4.4.7 | IndexedDB 封装，存密文信封 |
| 扫码 | 原生 API + ZXing 回退 | 兼容 iOS Safari |

---

## 4. 已知问题与待办

1. **密码学协议外部评审尚未进行**：`docs/key-protocol-spec.md` 已写好评审清单，需在 Phase 1 前完成。
2. **后端仍是开发骨架**：用户/登录状态在内存中，未接入 PostgreSQL；OPAQUE server setup 未持久化；无速率限制与审计落库。
3. **前端包体积 1.13 MB（gzip 357 KB）**：Vite 提示 chunk 超过 500 KB；Phase 1 需做端侧模型与 ZXing 的按需加载。
4. **真机扫码与浏览器矩阵未验证**：需在 iOS Safari、Android Chrome、桌面 Edge/Chrome 上跑通。
5. **依赖安装曾被沙箱拦截一次**（npm 试图清理 `node_modules` 下的旧目录）；代码与测试本身未受影响，后续若需重新安装依赖，请在允许 npm 清理的环境中执行。
6. **自托管部署脚本尚未编写**，列入 Phase 3。

---

## 5. 当前工程结构

```
equipment-checkout/
├── docs/
│   ├── threat-model.md
│   ├── key-protocol-spec.md
│   ├── pilot-workflow-checklist.md
│   └── phase0-validation-report.md
├── packages/crypto/          加密核心（可独立测试）
│   └── src/index.ts, index.test.ts
├── apps/api/                 零知识 API 骨架
│   └── src/app.ts, index.ts, app.test.ts
└── apps/web/                 PWA 技术验证台
    └── src/App.tsx, lib/{opaque,scanner,db}.ts
```

**启动方式：**
- `npm run dev:api` 启动 API（127.0.0.1:3001）
- `npm run dev:web` 启动验证台（127.0.0.1:5173）
- `npm test` / `npm run build` 全量验证

---

## 6. 进入 Phase 1 的门槛

- [ ] 外部密码学评审通过，无高危缺陷；
- [ ] 确定数据库与对象存储的密文表结构（按蓝图第 4 节）；
- [ ] 确定试点客户与 3 名分片管理员；
- [ ] 落实境内云账号、TLS、WAF 与日志策略；
- [ ] 完成浏览器矩阵与真机扫码冒烟测试。
