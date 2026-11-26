# 送审包清单与版本指纹

> 生成日期：2026-11-24
> 版本锁定方式：工程尚未初始化 git（`NO_GIT_REPO`），故以全文件 SHA-256 清单的聚合哈希作为版本指纹，等效于 commit hash。
> 评审报告中请引用此指纹，确保评审对象与实现一致。

## 版本指纹

```
BUNDLE_FINGERPRINT = 1ecad5975c01f21de7744c3aa99619d4832a83ce7772b5238379790a72d8d8cf
FILE_COUNT = 10
```

计算方式：**仅对下表 10 份评审材料**按路径排序，逐行拼接 `SHA256(file) + "  " + 相对路径`，对拼接后的 UTF-8 字节取 SHA-256。本清单、封面信及状态说明不参与指纹计算，因此后续补充管理性文件不会改变指纹。

## 文件清单

| SHA-256 | 相对路径 | 角色 |
|---|---|---|
| `cb0e549c31aa24f9da0345099f5aa0c227afa89909eb4be799eaa94eded94e7c` | `code/0001_init.sql` | 建议审：密文表结构、RLS、审计链约束 |
| `6994f950561fec8f05fe51de9b9cc75d6f6337aaea43e00184fe4bf214923dc2` | `code/crypto-index.ts` | 必审代码：浏览器端加密核心 |
| `ea4cc53554d6522f601fa9b96ef63b87a70b8fb64e9912a5a965318177cb9fac` | `code/server-crypto.ts` | 必审代码：服务端哈希与令牌（不接触业务密钥） |
| `c273eb7dd424fd0af9d982aa0b73b2db42c54e3e5792502ace64926633d73ccb` | `code/store.ts` | 必审代码：隔离、乐观锁、审计链原子追加 |
| `e6bb1e86efe3833d6e0f04ef13fb8ac3775bc3a4c4b4c42654232c6641cd621a` | `references/database-schema.md` | 必读：表结构与事务协议 |
| `cff2650350f5c7b3388a4ee669bcc36e872388c783fdf3ea81d14ff82ca6cab0` | `references/key-protocol-spec.md` | 必读：密钥协议规格 |
| `d83ef2fd51e5eca3cb2e5bcbfc53ed3f54827b7f445edf2699de3eca59b7909c` | `references/threat-model.md` | 必读：威胁模型 |
| `fe80d84572ed67ff0176b6cb4acdbca3e6c863592d6f24d5b1d8a48b30f98c85` | `review/README.md` | 主文档：评审目标、范围、准入判据 |
| `5146dd5b004a0f1ec2e8d2998cba6974f8f6244aca88ee918ede974d98cea26f` | `review/review-questions.md` | 主文档：16 个待答问题 |
| `93edd363be5c4621bd0733b2575266fd481d34f9f399aad77d63f45d8e2ccd41` | `review/test-vectors.md` | 主文档：可复现的测试向量 |

## 为什么附带 `references/` 与 `code/`

用户要求送审 `docs/review/` 下的三份文件。但 `review/README.md` 自身把 `key-protocol-spec.md`、`threat-model.md`、`database-schema.md` 列为**必读**，并把三段核心代码列为**必审代码**；`test-vectors.md` 的复现也依赖这些实现。若只投三份，评审方无法独立开展评审，会被迫来回索要材料。因此本包以三份 review 文件为主文档，附上其明确引用的材料，一并固定版本。

## 校验方式

评审方收到后可用任意 SHA-256 工具核对，例如：

```bash
sha256sum review/README.md
# 期望：fe80d84572ed67ff0176b6cb4acdbca3e6c863592d6f24d5b1d8a48b30f98c85
```

任一文件哈希与上表不符，说明版本不一致，应拒绝对该版本出具结论。
