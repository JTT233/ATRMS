# 送审状态

> 更新时间：2026-11-24

## 当前状态：材料就绪，尚未投递

**阻塞原因：** Agent 邮箱尚未开通。邮件工具调用返回 `not_bound`：「Agent 邮箱尚未开通，请引导用户在上方开通面板中完成开通，或前往『更多 - 我的邮箱』开通后再使用邮件工具」。

因此本次无法代为发出送审邮件，已完成的是**可直接投递的送审包准备**。

## 已完成

- [x] 固定送审版本：无 git，改用全文件 SHA-256 聚合指纹 `1ecad5975c01f21de7744c3aa99619d4832a83ce7772b5238379790a72d8d8cf`
- [x] 生成 `MANIFEST.md`：10 份材料逐文件哈希 + 版本指纹
- [x] 生成 `COVER-LETTER.md`：可直接复制的邮件正文草稿，含主题建议与重点关切
- [x] 打包 `docs/zero-knowledge-review-package-v0.1.zip`（12 个文件，SHA-256 `15cfa8b017eca258030d3210b90beab7177eec4259c988ded076476bb5dcea9c`）
- [x] 主文档为 `review/` 三份，另附其明确引用的 7 份必读/必审材料

## 待用户完成

- [ ] 开通 Agent 邮箱（开通面板或「更多 - 我的邮箱」），或自行用个人邮箱投递
- [ ] 选定外部评审机构 / 直接联系人，并约定报价、周期与 NDA
- [ ] 确认收件地址后，我可代为发送并附上 zip（邮件工具会要求你二次确认）
- [ ] 评审结论回来后，回填到 `docs/review/README.md` §7 与 `phase0-validation-report.md` 门槛清单

## 投递提示

- 若用个人邮箱自行发送：附件取 `docs/zero-knowledge-review-package-v0.1.zip`，正文取 `COVER-LETTER.md`；
- 请让评审方在报告中引用 `BUNDLE_FINGERPRINT`，避免版本错配；
- 不要只发 `review/` 三份——其中的 README 把协议规格、威胁模型、数据库设计列为必读，缺这些评审方无法独立开展工作。
