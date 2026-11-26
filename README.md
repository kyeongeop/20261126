# 多目标加固门禁 · Multi-Target Hardening Gate

发布制品管理平台（Release Artifact Management Platform）的发布门禁组件。
一个发布包同时包含 **可执行文件、共享库（`.so`）和静态库（`.a`）**，本工具按
**目标类型区分检查矩阵**，逐项检查：

- `PIE`（位置无关可执行；共享库对应 PIC/`ET_DYN`）
- `NX`（不可执行栈：`PT_GNU_STACK` / 成员的 `.note.GNU-stack`）
- `RELRO`（`PT_GNU_RELRO`）
- `BIND_NOW`（`DT_BIND_NOW` / `DF_BIND_NOW` / `DF_1_NOW`）
- `symbol_evidence`（符号证据：`.symtab` / `.dynsym` / 归档成员符号，含
  `__stack_chk_fail`、`__*_chk` 等加固符号与必需符号校验）

无法确认时状态输出为字符串 `unknown`。默认 **fail-closed**：任一**必需目标**
存在 `fail` 或 `unknown` 的必需检查，就阻止发布（退出码 `2`）。生成的 HTML
页面逐文件列出具体路径、类型、五项状态、原因码与符号证据。

## 依赖与约束

- 仅使用 Rust + Cargo，直接依赖严格限定为
  [`serde_json`](https://crates.io/crates/serde_json)、
  [`sha2`](https://crates.io/crates/sha2)、
  [`object`](https://crates.io/crates/object)（见 `Cargo.toml`）。
- 测试与演示只读取仓库内夹具 `fixtures/`，不读取 `/usr/bin` 等系统二进制。
- 错误码/状态字符串保持稳定，定义在 `src/codes.rs`，并由测试锁定。
- 依赖已 vendored 到 `vendor/`，配合 `.cargo/config.toml` 可完全离线构建/测试。

## 构建与测试

```bash
# 若 shell 中没有 cargo：
export PATH="$HOME/.cargo/bin:$PATH"

cargo build            # 编译库与 hardening-gate 可执行文件
cargo test             # 25 个单元/集成/CLI 测试，全部只读 fixtures/
cargo build --release  # target/release/hardening-gate
```

离线/隔离 HOME 也可构建（依赖全部来自 `vendor/`）：

```bash
CARGO_HOME=/tmp/mgate-cargo cargo test --offline
```

## 运行

```bash
# 无参数：读取 fixtures/release.json（混合发布，预期阻止，退出码 2），
# 写出 release-gate.json 与 release-gate.html
cargo run

# 仅门禁一个目录（递归识别 ELF / ar，自动分类）
cargo run -- --dir fixtures

# 使用指定发布清单
cargo run -- --manifest fixtures/release-good.json     # 全部达标，退出码 0
cargo run -- --manifest fixtures/release-unknown.json  # unknown 阻止，退出码 2

# 单个文件 + 自定义报告路径
cargo run -- fixtures/bin/app_hardened \
  --json /tmp/gate.json --html /tmp/gate.html
```

用浏览器打开 `release-gate.html` 即可看到“目标矩阵 + 逐项证据”页面，其中
列出每个具体文件（含 sha256 前缀）以及阻止发布的文件清单。

### 退出码（稳定）

| Code | 常量 | 含义 |
| ---: | --- | --- |
| `0` | `EXIT_PASS` / `GATE_PASSED` | 所有必需目标达标 |
| `1` | `EXIT_RUNTIME_ERROR` | IO/清单/报告写入错误（`E_PATH_NOT_FOUND`、`E_MANIFEST_*`、`E_REPORT_WRITE` …） |
| `2` | `EXIT_BLOCKED` / `GATE_BLOCKED` | 至少一个必需目标 `fail`/`unknown` |
| `64` | `EXIT_USAGE` | 命令行用法错误（`E_USAGE`） |

## 按目标类型区分的门禁矩阵

| 目标类型 | PIE | NX | RELRO | BIND_NOW | 符号证据 |
| --- | :-: | :-: | :-: | :-: | :-: |
| `executable` | 必需 | 必需 | 必需 | 必需 | 必需 |
| `shared_library` | 必需（按 PIC/`ET_DYN`） | 必需 | 必需 | 必需 | 必需 |
| `static_library`（`.a`） | N/A | 建议（成员 `.note.GNU-stack`） | N/A | N/A | **必需（主门禁）** |
| `relocatable`（`.o`） | N/A | 建议 | N/A | N/A | 必需 |

静态库/可重定位对象没有最终链接才确定的 PIE/RELRO/BIND_NOW，因此这些项输出
`not_applicable`（原因码 `*_NOT_APPLICABLE`），而 NX 通过每个成员的
`.note.GNU-stack` 段标志给出 `pass`/`fail`/`unknown`。

### 状态取值

`pass` · `fail` · `unknown`（无法确认，例如缺少 `PT_GNU_STACK`、符号表不可读、
空归档、截断/损坏 ELF）· `not_applicable`。目标汇总状态为
`pass`/`fail`/`unknown`/`not_gated`。

## 稳定错误码

- 制品/IO：`OK`、`E_PATH_NOT_FOUND`、`E_PATH_READ`、`E_NOT_A_FILE`、
  `E_ARTIFACT_EMPTY`、`E_ARTIFACT_PARSE`、`E_ARTIFACT_KIND_MISMATCH`
- 清单/输出：`E_MANIFEST_READ`、`E_MANIFEST_PARSE`、`E_REPORT_WRITE`、`E_USAGE`
- 检查原因码：`PIE_PASS`、`PIE_FAIL_ET_EXEC`、`PIE_UNKNOWN`、…、
  `NX_PASS_STACK_NOEXEC`、`NX_FAIL_STACK_EXEC`、…、
  `RELRO_PASS_GNU_RELRO`、`RELRO_FAIL_NO_GNU_RELRO`、
  `BIND_NOW_PASS`、`BIND_NOW_FAIL_LAZY_BINDING`、
  `SYMBOL_EVIDENCE_PASS_WITH_HARDENING_SYMBOLS`、
  `SYMBOL_EVIDENCE_FAIL_REQUIRED_MISSING`、
  `SYMBOL_EVIDENCE_UNKNOWN_EMPTY_ARCHIVE` 等。

完整目录见 `src/codes.rs`（`ALL_CODES` 也会写入 JSON 的 `error_code_catalog`）。

## 发布清单格式

```json
{
  "release": { "name": "mgate-platform", "version": "2.4.0" },
  "root": ".",
  "targets": [
    { "path": "bin/app_hardened", "required": true,
      "required_symbols": ["mgate_exec_anchor", "__stack_chk_fail"] },
    { "path": "static/libmgate_safe.a", "type": "static_library",
      "required": true, "required_symbols": ["mgate_static_add"] }
  ]
}
```

相对路径基于清单所在目录（可再用 `root` 前缀）解析；`required` 缺省为 `true`。
键名兼容 `artifacts`/`files`、`file`、`required_symbols`/`symbols` 等别名。

## JSON 报告

顶层包含 `schema_version`、`feature`（`multi-target-hardening-gate`）、
`feature_name_zh`（`多目标加固门禁`）、`gate`/`summary`、`targets`
（同时以 `artifacts`、`files` 别名暴露）、`ignored_files`、
`error_code_catalog`。每个目标含 `path`、`sha256`、`target_type`、`required`、
`status`、`release_blocks`、`reason_codes` 与有序的五项 `checks`
（`id`/`name`/`status`/`required`/`blocking`/`reason_code`/`evidence`/`symbols`）。

## 仓库结构

```
src/
  codes.rs      稳定退出码/错误码/原因码
  model.rs      Status/TargetType/Check/SymbolRef 与 JSON
  classify.rs   ELF/ar 魔数 + e_type + 文件名分类
  elf.rs        有界、大小端感知的 ELF 头/段/动态项解析
  symbols.rs    object：symtab/dynsym、加固符号、.note.GNU-stack
  archive.rs    object：ar 成员遍历与静态库证据聚合
  checks.rs     五项检查 + 按类型的需求矩阵
  artifact.rs   读文件、sha256、分类、汇总事实
  gate.rs       目标汇总与 fail-closed 发布决策
  manifest.rs   发布清单解析
  scan.rs       文件/目录/清单入口
  report.rs     GateReport 与稳定 JSON schema
  html.rs       自包含 HTML 页面
  cli.rs        可测试的命令行（bin 仅为薄封装）
tests/          fixtures_gate.rs + cli.rs（只读取 fixtures/）
fixtures/       真实 gcc/ar 夹具 + 三份清单 + build_fixtures.sh
vendor/         离线依赖
release-gate.html / release-gate.json  最近一次默认门禁产物
```

夹具由 `fixtures/build_fixtures.sh` 用显式开关编译，确保“加固/薄弱/未知”三类
结果都可复现：`app_hardened`（PIE+NX+RELRO+NOW+canary）、`app_weak`
（`ET_EXEC`+RWE 栈+无 RELRO/NOW）、`libmgate_{hard,weak}.so`、
`libmgate_{safe,plain,empty}.a`、`other/truncated.elf`、`other/notes.txt`。
