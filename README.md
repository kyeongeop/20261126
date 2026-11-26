# 动态库路径风险面板（dynlib_risk）

发布制品管理平台的“动态库路径风险”能力。解析 ELF 制品的 `DT_RPATH`、
`DT_RUNPATH`、`$ORIGIN` 变量与多级依赖链，按 ld.so 的搜索优先级还原
“优先搜索目录 → 实际加载库”的完整决策过程，并把每一条风险的来源
（制品、路径类型、目录、优先级序号）绘制到自包含 HTML 面板与 JSON 报告中。

仅使用 Rust + Cargo 实现，依赖 `serde` / `serde_json` / `sha2` / `object`，
只读取仓库内 `fixtures/` 夹具，错误码与风险编码保持稳定。

## 构建与运行

```bash
cargo build --release
cargo run -- --repo-root . --artifact fixtures/bin/app \
  --config fixtures/allowed_directories.json \
  --json-out artifacts/dlr/report.json \
  --html-out artifacts/dlr/panel.html
```

不指定 `--json-out/--html-out` 时，JSON 报告打印到标准输出，扫描摘要打印到
标准错误；任何失败都以稳定错误码 JSON 输出到标准错误并返回非零退出码。

## 配置

配置文件为 JSON（见 `fixtures/allowed_directories.json`）：

- `allowed_directories`：允许目录名单。支持绝对路径（匹配变量展开后的目录），
  以及 `$ORIGIN/...` 形式的相对模式（匹配原始条目）。
- `ld_library_path`：模拟 `LD_LIBRARY_PATH` 搜索层，默认空，不启用该层。
- `max_depth`：依赖递归最大深度，默认 16。

## 搜索顺序与风险模型

面板按 glibc ld.so 语义排列候选目录：

1. 依赖链上所有对象的 `DT_RPATH`（旧机制，沿依赖链继承，先于环境变量）；
2. `LD_LIBRARY_PATH`（由配置注入，默认空）；
3. 直接依赖对象自身的 `DT_RUNPATH`（新机制，不继承）；
4. 系统默认目录（仅展示，不参与仓库内解析）。

重点覆盖的风险：

- 空路径项：冒号串中的空条目被 ld.so 解释为当前工作目录，加载结果随部署机器变化；
- `$ORIGIN` 展开：支持 `$ORIGIN` 与 `${ORIGIN}`，标记未展开变量与逃逸仓库根的目录；
- 多级依赖：还原祖先 RPATH 对深层依赖的继承影响与 RUNPATH 的不继承差异；
- 版本遮蔽：同一 SONAME 在多个候选目录存在时，首个命中决定实际加载版本；
- 缺失依赖：仓库内候选目录均未命中时给出 DLP2007，系统基础库（libc 等）不计入。

## 稳定编码

编码一旦发布只增不改、编号不复用。

| 编码 | 含义 |
| --- | --- |
| DLP1001 | 参数无效 |
| DLP1002 | 路径逃逸仓库根 |
| DLP1003 | 路径不存在 |
| DLP1004 | 非 ELF 文件 |
| DLP1005 | ELF 解析失败 |
| DLP1006 | 动态段/字符串表读取失败 |
| DLP1007 | 配置解析失败 |
| DLP1008 | IO 错误 |
| DLP1009 | 依赖环或超过最大深度 |
| DLP1010 | 预留编号，不复用 |

| 编码 | 风险 |
| --- | --- |
| DLP2001 | 空路径项 |
| DLP2002 | 使用已废弃的 DT_RPATH |
| DLP2003 | 依赖解析回退当前工作目录 |
| DLP2004 | 搜索目录逃逸仓库 |
| DLP2005 | 未展开的动态变量 |
| DLP2006 | 版本遮蔽/未授权目录加载 |
| DLP2007 | 依赖在仓库内无法解析 |
| DLP2008 | 目录不在允许名单内 |
| DLP2009 | 依赖环 |
| DLP2010 | 多级依赖受祖先 RPATH 影响 |

## 仓库布局

- `src/elf.rs`：基于 `object` 的 ELF 动态段解析，含 strip/无节区表回退逻辑；
- `src/paths.rs`：RPATH/RUNPATH 条目拆分与 `$ORIGIN` 展开；
- `src/analyzer.rs`：依赖链遍历、候选目录解析与风险识别；
- `src/report.rs`：JSON 报告与 HTML 面板渲染；
- `src/config.rs`：允许目录配置与仓库沙箱；
- `fixtures/`：仓库内 ELF 夹具与重建脚本 `build_fixtures.sh`；
- `tests/panel_scan.rs`：端到端测试，只依赖夹具与本仓库二进制。

## 测试

```bash
cargo test
```

夹具随仓库提交；需要重建时在 Linux + gcc 环境执行
`./fixtures/build_fixtures.sh`。
