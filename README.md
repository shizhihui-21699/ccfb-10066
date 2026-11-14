# 云策略分析器 · IAM Policy Analyzer

一个纯前端（React + TypeScript + Vite）的云 IAM 策略分析工具。导入策略 JSON 后，它回答两类问题：

- **正向**：某个身份，能不能对某个资源执行某个操作？为什么？
- **反向**：谁能对某个资源执行某个操作？

结论会给出 `允许 / 显式拒绝 / 隐式拒绝 / 无法确定` 四档判定，并附带一条从请求上下文到最终结论的理由链。

```bash
npm install
npm run dev        # 开发服务器
npm test           # 80 个引擎 / 组件测试
npm run build      # 类型检查 + 生产构建
```

## 功能

### 求值模型

| 能力 | 说明 |
| --- | --- |
| Action / NotAction | 大小写不敏感，支持 `*` / `?` |
| Resource / NotResource | ARN 六段分别匹配（账号通配不会溢出到资源段）；S3 五段 ARN 退化为整串匹配 |
| Principal / NotPrincipal | `"*"`、账号 ID、账号根 ARN、用户 / 角色 ARN、角色会话 ARN、`Service` / `Federated` / `CanonicalUser` |
| 策略变量 | `${aws:username}`、`${PrincipalTag/team}`、`${*}` / `${?}` / `${$}`；无值键解析为 null 且不参与匹配 |
| 条件运算符 | 字符串、数值、日期、布尔、IP/CIDR（含 IPv6）、ARN、Binary、Null |
| 否定与修饰 | `StringNotEquals`、`ArnNotLike` 等否定形式；`...IfExists`；`Null` |
| 集合运算符 | `ForAllValues:`、`ForAnyValue:`（含与否定运算符的组合） |
| 显式拒绝 | 任意适用策略中的 `Deny` 命中即拒绝，优先级最高 |
| 权限边界 | 与身份策略取交集；同账号资源策略授权给用户 ARN / 角色会话 ARN 时不受其隐式拒绝限制 |
| 组织级 SCP | 根 → OU → 账号逐层求值：任一层显式拒绝即拒绝，且**每一层都必须有显式 Allow** |
| 资源策略 | 同账号可直接授权；跨账号还要求调用方身份策略允许 |
| 信任策略 | `sts:AssumeRole` 同时要求调用方身份策略允许与目标角色信任策略匹配 |
| 三值逻辑 | 未提供的条件键 → `unknown` → 结论 `无法确定` 并列出缺少的键 |

### 界面

- **概览**：数据集统计、组织 / SCP 层级、样例中内置的陷阱（点击直接跳转到预填好的查询）
- **谁能做什么**：选身份 / 操作 / 资源 / 条件键，得到结论、理由链、语句级明细
- **反查**：对全部用户与角色逐一求值，按结论排序，可筛选、可按名称 / 账号 / 标签过滤
- **策略库与导入**：浏览 / 搜索全部策略；导入单个策略文档并附加到指定身份或资源；导入整套数据集

导入的策略会立即参与求值。缺失条件键有两种处理方式：

- **按未知处理**（默认）：结论为“无法确定”，并列出需要补充的键 —— 适合排查“我还需要知道什么”
- **按不存在处理**：严格按 AWS 文档语义求值（正向运算符为假、否定运算符为真、`ForAllValues` 对空集合为真）

## 样例数据集

`src/data/sample-dataset.json` 由 `scripts/generate-sample.mjs` 生成（`npm run gen:sample`），包含 4 个账号、4 个 OU、302 条策略、366 条语句、18 个用户、13 个角色与 3 个资源策略挂载。账号、资源均为虚构。

### 样例中的陷阱

这些语句**看着安全，实际放开了权限**。概览页可以一键跳转验证：

1. **SCP 前缀缺口** — `Prod-Guardrails` 的 `ProtectProdBucketPolicies` 只匹配 `arn:aws:s3:::prod-*`，而真正的生产桶叫 `production-payments-archive`。于是生产桶的桶策略仍可被改写。
2. **权限边界前缀同样写错** — `Admin-Boundary` 只拒绝 `prod-*` 上的删除，`StorageAdmin` 因此可以删除 `production-payments-archive` 这个桶本身。
3. **`ForAllValues` 缺少 `Null` 检查** — `Tagged-Upload-Policy` 本意是“只在携带指定标签时允许上传”，但请求不带任何标签时 `ForAllValues` 对空集合为真，等于不要求标签。
4. **`NotAction` 漏掉桶级动作** — `Shared-ReadOnly-Objects` 排除了 `PutObject` / `DeleteObject`，看起来是只读，但 `PutBucketPolicy`、`DeleteBucket` 等桶级动作不在排除列表里。
5. **账号字段通配** — `Deployer-Prod` 的 `AssumeDeployRoles` 写成 `arn:aws:iam::*:role/ProdDeployer`，本意是同账号两个角色，实际允许扮演任意账号下的同名角色。
6. **IP 条件混入 `0.0.0.0/0`** — `Corp-Network-Prod-Access` 的 `aws:SourceIp` 列表包含 `0.0.0.0/0`，“仅公司网段”实际对全互联网开放。
7. **资源策略公开读** — `production-payments-archive` 的桶策略 `Principal: "*"` 且只要求 TLS，是公开读而非同账号读取。
8. **`BoolIfExists` 让 MFA 要求失效** — `DeletionWorker` 的 `DeleteObjectsWithMfa` 用 `BoolIfExists` 检查 `MultiFactorAuthPresent`：键不存在时条件为真，因此不带 MFA 也能删除。

## 代码结构

```
src/
  engine/
    types.ts       策略 / 数据集 / 请求上下文 / 结论类型
    wildcard.ts    通配与 ARN 匹配（含字面量转义）
    variables.ts   策略变量展开与 null 语义
    conditions.ts  条件运算符解析与求值（含集合运算符、IP/CIDR、三值组合）
    statement.ts   单条语句求值：Action / Resource / Principal / Condition
    decision.ts    结论合成：拒绝优先、边界交集、SCP 逐层、资源策略、反查
    import.ts      策略与数据集的解析校验
  components/      概览 / 正向查询 / 反查 / 策略库 四个页面与共享组件
  data/            生成的样例数据集
scripts/
  generate-sample.mjs  样例数据集生成器
```

求值引擎不依赖 React，可以独立在 Node 中调用（见 `src/engine/engine.test.ts`）。

## 已知边界

这是一个分析工具，不是 AWS 授权引擎的替代品：

- **未建模服务级细节**：某些服务的资源级权限、`aws:ResourceTag` 的实际注入时机、服务关联角色等未模拟。
- **`ForAllValues` 空集合与 `unknown` 的取舍**：未知键与缺失键不同，工具用 `unknown` 表达，避免把“没告诉我”误判为“允许”。
- **SCP 的 Allow 语义**：按组织文档要求每一层都有显式 Allow；现实中被移除 `FullAWSAccess` 的层级确实会阻断一切。
- **假定资源归属**：跨账号判断依赖资源 ARN 第 5 段或数据集中的 `resources` 登记；S3 桶必须登记才能判断归属，否则按同账号处理。
- **数据规模**：反查对每个身份独立求值，适合数百个身份、数百条策略的中等规模；更大规模需要索引化。

## 测试

```
src/engine/engine.test.ts    通配、变量、条件运算符、语句语义、结论合成、信任策略、缺键模式、边界豁免、反查、8 个样例陷阱
src/engine/import.test.ts    策略 / 数据集解析与校验
src/components/render.test.tsx  四个页面的服务端渲染冒烟测试
```
