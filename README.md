# depguard — 依赖混淆配置检查器与受保护内部仓库

项目解析器把公共包和内部包混在同一命名空间时，攻击者可以在公共仓库抢注与内部包
同名的包（dependency confusion / 依赖混淆），诱导安装器从公共源拉取恶意版本。

本仓库用 **Go 1.24（仅标准库）** 实现了两部分：

1. **安装前配置检查能力**：读取依赖清单、锁文件、镜像/仓库声明、公共仓库目录夹具和
   内部索引，精确识别四类风险，并在安装前给出“被替换来源 → 候选安全来源”。
2. **带依赖混淆保护的内部软件包仓库**：基于 `net/http` 提供发布/元数据/tarball 服务，
   用 `archive/tar` 校验归档、用 `crypto/sha256` 固定内容摘要；对内部保留命名空间
   **绝不回退/代理到公共仓库**。

只使用 Go 标准库（仓库没有既有第三方依赖），所有外部仓库信息都来自 `fixtures/`
本地夹具，离线可跑，不需要网络。

## 快速开始

```bash
go test ./...                          # 全部单元/HTTP/CLI 测试（-race 也通过）

# 有问题的示例工程：8 个 error + 1 个 warning，退出码 1（可用于安装门禁）
go run . check -config fixtures/projects/unsafe/depguard.json

# JSON 契约输出
go run . check -config fixtures/projects/unsafe/depguard.json -json

# 干净工程：0 findings，退出码 0
go run . check -config fixtures/projects/safe/depguard.json

# 按候选来源重写锁文件（resolved + integrity，并清除过期 fallback 标记）
go run . fix -config fixtures/projects/unsafe/depguard.json -out /tmp/fixed-lock.json

# 用 fixtures 里的真实 tar 填充本地仓库（可重复执行）
go run . seed -config fixtures/projects/unsafe/depguard.json -data ./data

# 启动受保护内部仓库（不带任何子命令时等价于用默认参数执行 serve）
go run . serve -addr 127.0.0.1:8080 -data ./data \
  -prefix @acme/ -exact acme-billing \
  -public-catalog fixtures/public-catalog.json

# 把一个目录打成 tar 并输出 sha256
go run . pack -src fixtures/pkgroot/acme-core -name @acme/core -version 1.4.0 -out /tmp/core.tar
```

退出码（`check`）：`0` 通过；`1` 存在 error 级发现（应阻断安装，`--strict` 时
warning 也阻断）；`2` 用法或运行时错误。
CI 中建议先 `go build -o depguard .` 再执行 `./depguard check ...`，以避免
`go run` 包装器向 stderr 打印 `exit status 1`，并直接获得精确退出码。

## 四条精确规则

规则 ID / slug / 中文名是稳定契约，会同时出现在文本、JSON 和测试中。

| ID | 名称 | 精确触发条件 | 不会误报的情况 |
|----|------|--------------|----------------|
| `DG101` | `undeclared-mirror` 未声明镜像 | 锁文件里存在绝对 `resolved` URL，但其 host+路径前缀**匹配不到** `registries[]` 中任何已声明仓库/镜像 | 来自已声明公共仓库 `npmjs` 或已批准镜像 `acme-cn-mirror` 的包（即使是外部包） |
| `DG102` | `same-name-public-package` 同名公共包 | 包名被 `namespace.prefixes`（前缀/scope）或 `namespace.exact`（精确保留）判定为内部，**且** 公共目录夹具中确实存在完全同名的包 | `lodash`/`express`/`dayjs` 等非内部名字，即便它们是公共包也绝不判风险 |
| `DG103` | `internal-prefix-fallback` 内部前缀回退 | 包名命中**声明的内部前缀**，且出现下列之一：锁条目标记 `via_fallback`/选择原因含 fallback/404、或其 resolved 锚定到 `kind=public` 的仓库；另外 `namespace.fallback="public"` 会产生一条配置级 warning | 非前缀的普通公共包走公共源；`fallback="deny"` 且内部前缀包来自内部源 |
| `DG104` | `lockfile-source-override` 锁文件覆盖 | 仅针对**受保护内部包**：锁文件 `resolved` 锚定的仓库不是配置路由出的内部仓库（来源覆盖），或锁文件 `integrity` 中的 sha256 与内部索引公布的摘要不一致（摘要覆盖） | 内部包来源正确且摘要一致；外部包的源漂移归 DG101，不套 DG104，避免重复/扩大化 |

“规则足够具体、不把所有外部包判为风险”由两点保证：

- **命名空间只来自显式配置**：前缀是字面前缀匹配（`@acme/`、`go.acme.dev/`、
  反向域名 `com.acme.` 均可），精确保留走 `exact`；不会因为“看起来像内部名”
  或“来自外网”就打分。`acme-something` 这类不匹配前缀的名字不会被当成内部包。
- **来源只与声明集合比对**：正常公共依赖走声明的 `npmjs`、经批准镜像走
  `acme-cn-mirror`，都是安全的；只有“未声明 host”或“内部名被公共/他源覆盖”才报。
  除 `depguard.json` 的 `registries[]` 外，设置 `"npmrc": ".npmrc"` 还会解析真实
  `.npmrc` 的 `registry=` 与 `@scope:registry=` 行并并入声明来源（见 `npmrc.go`）。

`TestExternalPackagesNotFlagged`、`TestSafeFixtureHasNoFindings` 专门锁定该精度。

## 安装前的“被替换来源 → 候选来源”

每次检查都会为可处置的发现生成候选来源，并在报告末尾汇总成替换计划
`replacements[]`。JSON 字段同时给出两端：

- `replaced_source`：当前锁文件/配置里**将被替换掉的风险来源**。在混淆攻击中，
  它正是“顶替内部源的同名公共/未声明候选来源”，即**被替换的（内部）来源位置上
  实际出现的那个候选源**。
- `candidate_source`：建议改用的安全候选来源；内部候选带内部索引/在线仓库给出的
  `sha256` 与 `verified=true`，外部包则给出来源声明公共仓库的等价 URL。

也就是说，报告同时回答了“是哪个越界候选源顶替了应有来源”和“安装前应换回哪个
带摘要的安全来源”。

典型文本输出：

```text
[DG101] (error) 未声明镜像 random-utils@1.2.0 ...
    被替换来源 (replaced) : https://mirror.shady.test/random-utils/-/random-utils-1.2.0.tgz
    候选来源   (candidate): https://registry.npmjs.org/random-utils/-/random-utils-1.2.0.tgz

[DG102] (error) 同名公共包 @acme/ui@2.0.0 ...
    被替换来源 (replaced) : https://registry.npmjs.org/@acme/ui/-/ui-2.0.0.tgz
    候选来源   (candidate): https://pkgs.acme.test/@acme/ui/-/ui-2.0.0.tgz
                            (sha256:b4a09cf0…3eddd1, verified-internal)

== 安装前来源替换计划 (replacement plan) ==
- @acme/ui@2.0.0  [DG102,DG103,DG104]
    替换前/被替换: https://registry.npmjs.org/@acme/ui/-/ui-2.0.0.tgz
    替换为/候选  : https://pkgs.acme.test/@acme/ui/-/ui-2.0.0.tgz (…verified-internal)
```

`depguard fix` 会把该计划真正写回 npm 风格或归一化锁文件的 `resolved`/`integrity`，
并清除已失效的 `via_fallback` 标记。重写后 DG101/DG103(包级)/DG104 清零；DG102
公共抢注仍然存在，因为它需要在公共仓库侧占用/下架包名，而不是改本地锁文件。
完全修复后的状态由 `fixtures/projects/safe` 表达（公共目录中已无 Acme 同名包、
`fallback="deny"`、摘要全部一致），检查结果为 0 findings。

作为真正的“安装前”门禁，可在 `package.json` 接入 preinstall 钩子（检查不通过即
非零退出，`npm install` 会中止）：

```json
{ "scripts": { "preinstall": "depguard check -config depguard.json" } }
```

## 本地夹具与判定矩阵

`fixtures/` 提供离线、可复现的一整套样例：

- `public-catalog.json`：模拟公共仓库快照，**故意**包含抢注的 `@acme/ui@4.0.0-evil`
  和 `acme-billing@9.9.9`，以及正常公共包。
- `public-catalog-safe.json`：同名内部包已在公共侧被保留/下架的干净视图。
- `internal-index.json`：内部可信索引，sha256 与 `fixtures/tarballs/*.tar` 真实一致
  （由 `depguard pack` 生成）。
- `projects/unsafe/`：npm 风格 `package.json` + `package-lock.json`（lockfileVersion 3）。
- `projects/safe/`：全部来源/摘要正确的对照工程。
- `pkgroot/` 与 `tarballs/`：真实打包源与 tar 夹具。

unsafe 工程刻意让每条规则都有“标准正例”，并安排了隔离用例：

| 包 | 分类 | 锁文件来源 | 命中 |
|----|------|-----------|------|
| `@acme/core` | 前缀内部 | 内部源正确，但 integrity 被改成全 0 | 仅 `DG104`（摘要覆盖） |
| `@acme/ui` | 前缀内部，公共有同名 | 公共源 + fallback 标记 | `DG102` `DG103` `DG104` |
| `acme-billing` | `exact` 内部（无前缀），公共有同名 | 未声明 `mirror.evil.test` | `DG101` `DG102` `DG104`（不触发 DG103） |
| `random-utils` | 普通外部包 | 未声明 `mirror.shady.test` | 仅 `DG101` |
| `lodash` `express` | 普通外部包 | 声明的 `npmjs` | 无 |
| `dayjs` | 普通外部包 | 已声明批准镜像 `mirrors.acme.test/npm` | 无 |

## 内部仓库的依赖混淆保护

`depguard serve` 启动 `net/http` 服务（见 `server.go`、`guard.go`、`store.go`）：

- `GET /healthz`：健康检查与保护策略标识。
- `GET /v1/packages`：已托管内部包名列表。
- `GET /v1/release?name=&version=`（version 可空=最新）：发布元数据 JSON。
- `GET /v1/tarball?name=&version=`：返回 tar，带 `Digest: sha256:…` 与
  `X-Checksum-SHA256`，下载时重新计算摘要并与发布记录比对。
- `PUT/POST /v1/publish?name=&version=`：body 为 tar；可用 `-publish-token`
  或 `DEPGUARD_PUBLISH_TOKEN` 开启 `Authorization: Bearer` / `X-Publish-Token`。
  同名同版本重复发布返回 `409`（不可变）。

保护核心是 `Guard.Evaluate`：

- 命中 `prefixes`/`exact` 的保留名永远是 internal-only。即使内部仓库没有该版本，
  也只返回 `404` + `dependency_confusion_protection.blocked=true` 与响应头
  `X-Depguard-Protection: reserved-no-public-fallback`，**不会**请求任何公共上游；
  响应还会用公共目录夹具给出 `public_catalog_has_same_name` 证据。
- `-upstream` / `-allow-public-fallback` 的公共回退/代理只对**非保留名**生效；
  保留名在代码路径上先被拦截。测试用 httptest 上游间谍断言保留名的上游调用数为 0，
  而非保留名 `lodash` 仍可走一次显式回退，证明拦截是命名空间相关而非把代理整个关掉。

`archive/tar` 用于发布时 `VerifyTar`（拒绝绝对路径与 `../` 路径穿越条目）和
`BuildTar`（确定性打包）；`crypto/sha256` 用于 `DigestBytes`/`DigestReader`，
产物摘要格式统一为 `sha256:<hex>`，并兼容 SRI 的 `sha256-<base64>`，但不会把
`sha512-…` 误当成 sha256 比较，避免错误告警。

检查器还提供 `HTTPResolver`：直接查询在线仓库 `/v1/release` 得到已验证候选，
可通过 `WithResolver(...)` 注入，形成“检查 → 在线内部仓库取候选摘要 → 安装门禁”
的闭环；`TestCheckerUsesHTTPResolverCandidate` 覆盖该集成路径。

## 代码结构

根目录是单一 `package main`（`go run .` 即可），同时保留清晰的文件分工：

- `model.go`：配置/清单/锁/目录/报告等稳定 JSON 模型与四个规则常量。
- `names.go`：命名空间分类、仓库/镜像 URL 锚定、候选 URL 推导。
- `parsers.go`：归一化格式 + npm `package.json` / `package-lock.json`(v1/v3) 解析。
- `npmrc.go`：`.npmrc` 的 `registry=`/`@scope:registry=` 解析与来源合并。
- `config.go`：配置与夹具加载、相对路径解析。
- `checker.go` `checks.go`：四条规则、汇总与替换计划。
- `report.go`：中文文本报告；JSON 直接由 `Report` 序列化。
- `rewrite.go`：把候选来源写回锁文件。
- `archive.go`：`archive/tar` 安全打包/校验 + `crypto/sha256` 摘要。
- `guard.go` `store.go` `server.go` `resolver.go`：保护策略、内容存储、HTTP 服务与在线解析。
- `main.go` `cli_commands.go` `cli_serve.go` `cli_pack.go` `cli_seed.go`：CLI 子命令。
- `*_test.go`：23 个测试覆盖规则矩阵、精度反例、`.npmrc`、tar/摘要、锁文件修复、
  HTTP 发布/下载/不可变、保留名零回退与 CLI 退出码/JSON 契约。

## 设计说明

- 模块名 `depguard`，`go 1.24`，**零第三方依赖**、无 `go.sum`。
- 不联网：公共仓库“是否存在同名包”由 `fixtures/public-catalog*.json` 判定；
  在线路径只访问你自己启动的内部仓库。
- 配置 schema 为 `depguard.config/v1`，报告 schema 为 `depguard.report/v1`，
  字段使用 snake_case，可直接作为 CI 门禁或进一步处理的契约。
