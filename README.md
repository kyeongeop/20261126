# 压缩包结构检查 · archive-structure-check

发布制品管理平台的上传前结构门禁。发布上传此前只校验外层压缩包的
SHA-256；本组件在哈希之外打开压缩包，解析内部成员树，并把每个问题标记到
**具体成员序号、原始名称和规范化路径**。

仅使用 Rust + Cargo，直接依赖为 `serde_json`、`sha2`、`object`。功能运行期
只读取仓库内的 `fixtures/` 夹具；所有夹具路径都经过词法 confinement 和
canonicalize 校验，绝对路径、`..` 与指向仓库外的符号链接都会被拒绝。

## 检查内容

- 绝对路径：Unix `/...`、Windows 盘符 / UNC、混合反斜杠分隔符。
- 路径穿越：任意 `..` 段，以及越过压缩包根的父目录引用。
- 符号链接/硬链接指向：绝对目标、目标逃逸、悬空目标、循环、缺少硬链接目标。
- 重复路径：规范化后的重复成员、仅大小写不同、文件/目录前缀冲突。
- 异常权限：setuid、setgid、sticky、world/group writable、缺少所有者读位、
  目录缺少搜索位、可执行对象缺少执行位、非二进制带执行位、文件类型位冲突。
- 其他：空成员名、NUL、非 UTF-8 名称、加密成员、设备/FIFO 等特殊文件、
  CRC/解压错误、带二进制扩展名但 `object` 无法解析的成员。
- 外层 SHA-256：继续校验清单声明的摘要，不一致同样阻断。

## 重新上传对比

修复包上传清单设置 `"upload_type": "fix"`（或 `"reupload": true`）并声明
`previous` 上版压缩包。检查器会同时解析上版和当前版本，报告：

- 新增/删除/类型变化/权限变化/链接目标变化/内容变化；
- 上版已修复的问题、仍然存在的问题、修复包新引入的问题；
- 删除成员、类型变化、新结构问题为阻断项；新增成员、权限/链接变化为警告；
  正常修复导致的内容变化为提示，不影响发布结论。

`same_structure` 只在成员集合、类型、权限和链接目标不变时为 `true`；
单纯内容变化不算结构变化。

## 构建与测试

```bash
cargo build
cargo test
cargo run -- check --fixtures fixtures --manifest upload.json
```

本机若未配置 rustup 默认工具链，可直接使用：

```bash
export PATH="$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"
cargo test
```

测试只依赖仓库内夹具和本仓库编译出的 CLI。

## CLI

```bash
# 默认读取 fixtures/upload.json；通过/阻断分别退出 0/2
cargo run

# 首版上传
cargo run -- check --fixtures fixtures --manifest upload.json \
  --json artifacts/structure-report.json --html artifacts/structure-report.html

# 恶意 ZIP（阻断，退出码 2）
cargo run -- check --fixtures fixtures --manifest upload-bad.json

# 修复包：与上版结构对比
cargo run -- check --fixtures fixtures --manifest reupload.json
cargo run -- check --fixtures fixtures --manifest reupload-regression.json

# 单包扫描 / 双包对比
cargo run -- scan --fixtures fixtures --archive archives/agent-2.4.0.tar.gz
cargo run -- compare --fixtures fixtures \
  --previous archives/agent-2.4.0.zip \
  --archive archives/agent-2.4.1-bad.zip

# 列出夹具清单
cargo run -- list --fixtures fixtures
```

通用参数：`--repo-root`（默认当前目录）、`--fixtures`（默认 `fixtures`）、
`--json`、`--html`。`archive-check` 会把运行期错误以 JSON 写到 stderr；
结构报告写到 stdout 或指定文件。

## 上传清单

```json
{
  "schema_version": 1,
  "release": { "name": "agent", "version": "2.4.0", "build": "release-1" },
  "archive": {
    "path": "archives/agent-2.4.0.zip",
    "sha256": "<64 hex characters>"
  }
}
```

修复包增加：

```json
{
  "upload_type": "fix",
  "archive": { "path": "archives/agent-2.4.0-fix.zip", "sha256": "..." },
  "previous": { "path": "archives/agent-2.4.0.zip", "sha256": "..." }
}
```

`archive`/`previous` 也接受字符串路径；`archive_path`、`previous_archive`、
`base` 等别名兼容。所有路径相对 fixture 根解析，不能以 `/` 开头或包含 `..`。

## 稳定错误码

运行时错误码是外部契约，只增不改、编号不复用。完整目录也会写入 JSON 的
`error_code_catalog`。

| 编码 | 名称 | 含义 |
| --- | --- | --- |
| `ARC1001` | `INVALID_ARGUMENT` | CLI 参数错误（退出 64） |
| `ARC1002` | `FIXTURE_ROOT_NOT_FOUND` | fixture 根不存在或不可解析 |
| `ARC1003` | `MANIFEST_NOT_FOUND` | 清单不存在 |
| `ARC1004` | `MANIFEST_READ_FAILED` | 清单读取失败 |
| `ARC1005` | `MANIFEST_JSON_INVALID` | 清单不是合法 JSON |
| `ARC1006` | `MANIFEST_SCHEMA_INVALID` | 清单字段/类型/模式错误 |
| `ARC1007` | `PATH_OUTSIDE_FIXTURE_ROOT` | 夹具路径逃逸根目录 |
| `ARC1008` | `ARCHIVE_NOT_FOUND` | 压缩包不存在 |
| `ARC1009` | `ARCHIVE_READ_FAILED` | 压缩包读取失败 |
| `ARC1010` | `UNSUPPORTED_ARCHIVE_FORMAT` | 不支持的容器格式 |
| `ARC1011` | `ARCHIVE_PARSE_FAILED` | ZIP/TAR/GZIP 解析失败 |
| `ARC1012` | `ARCHIVE_HASH_MISMATCH` | 外层哈希与声明不一致 |
| `ARC1013` | `PREVIOUS_ARCHIVE_REQUIRED` | 修复包未声明上版 |
| `ARC1014` | `OUTPUT_WRITE_FAILED` | 报告写入失败 |
| `ARC1015` | `INTERNAL` | 内部错误 |

## 结构问题码

结构问题写入 `findings`（并同步到 `issues`），每个问题带
`member_index`、`member_name`、`member_path` 和稳定编码：

`ARC2001` absolute path · `ARC2002` traversal · `ARC2003` NUL ·
`ARC2004` separator ambiguity · `ARC2005` symlink absolute ·
`ARC2006` symlink escape · `ARC2007` dangling link · `ARC2008` symlink loop ·
`ARC2009` duplicate path · `ARC2010` case-insensitive duplicate ·
`ARC2011`/`ARC2012` hardlink absolute/escape · `ARC2013` hardlink missing ·
`ARC2014` path prefix conflict · `ARC2015` setuid · `ARC2016` setgid ·
`ARC2017` sticky · `ARC2018` world writable · `ARC2019` group writable ·
`ARC2020` missing owner read · `ARC2021` directory not searchable ·
`ARC2022` executable binary without exec bit · `ARC2023` exec bit on non-binary ·
`ARC2024` mode/type mismatch · `ARC2025` special file · `ARC2026` encrypted ·
`ARC2027` non-UTF-8 path · `ARC2028` member content error · `ARC2029` CRC ·
`ARC2030` binary parse failed · `ARC2031` empty name · `ARC2032` archive hash.

重传对比码：`ARC3001` added · `ARC3002` removed · `ARC3003` type changed ·
`ARC3004` mode changed · `ARC3005` link target changed ·
`ARC3006` content changed · `ARC3007` new issue · `ARC3008` issue remains ·
`ARC3009` issue fixed。

严重级别为 `blocking`（阻断）、`warning`（警告）、`info`（提示）。
只有 `blocking` 会令 `verdict` 为 `blocked`、CLI 退出码为 `2`。

## 仓库结构

```
src/
  archive.rs   容器格式、成员模型、格式检测
  inflate.rs   有界 DEFLATE / gzip（不引入 flate2）
  zip.rs       ZIP 中央目录、Unix 权限、符号链接、ZIP64
  tar.rs       ustar/GNU/PAX、长文件名、硬链接
  path.rs      路径/链接目标的词法分析与 fixture confinement
  inspect.rs   object：ELF/Mach-O/PE/COFF 元数据
  check.rs     成员级路径、链接、重复、权限检查
  compare.rs   修复包与上版结构对比
  manifest.rs  上传清单解析
  report.rs    JSON 报告与稳定 schema
  html.rs      自包含 HTML 报告
  cli.rs       check/scan/compare/list
tests/
  structure_checks.rs  端到端、错误码契约与 CLI 退出码
fixtures/
  build_fixtures.py    可重复生成夹具
  archives/            干净 ZIP/TAR.GZ、恶意 ZIP/TAR、修复包
  payload/             真实 gcc ELF/共享库与文本成员
  upload*.json         上传清单
  reupload*.json       修复包清单
```

## 支持格式与限制

- 支持 ZIP（store/deflate、ZIP64）、tar、tar.gz/tgz。
- gzip 只支持单个 member；bzip2/xz/zstd 因依赖限制不解析，会返回
  `ARC1011`。加密 ZIP 成员会被标记 `ARC2026` 且不读取内容。
- 解压输出上限 512 MiB，输入上限 2 GiB；防止压缩炸弹耗尽内存。
- 路径检查全程不落盘、不解压到宿主机文件系统。
