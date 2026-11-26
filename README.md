# 发布签名准入

面向发布制品管理平台的可配置签名准入引擎。每条产品线可以配置独立的发布者
范围、签名数量、必需发布者、签名算法、策略有效期和撤销状态。发布前统一调用
同一入口，返回完整、有序的策略命中链；链中任一适用策略拒绝时，最终结果一定
为拒绝。

本模块只做准入决策，不执行密码学验签。调用方应先将密码学验签结果转换为本模块
的签名元数据；模块会校验签名与制品 SHA-256 的绑定、策略范围、有效期和撤销状态。

## 快速开始

```bash
cargo test
cargo run -- --config tests/fixtures/policies.json \
  --request tests/fixtures/request_allow.json
```

CLI 输出 JSON 策略链。退出码固定为：

- `0`：允许发布
- `1`：拒绝发布
- `2`：配置、请求或夹具读取错误

Rust 调用：

```rust
let report = release_signature_admission::preflight(
    policy_json,
    request_json,
)?;
if !report.is_allowed() {
    eprintln!("{}", report.to_json_string_pretty());
}
```

也可以构造 `AdmissionEngine` 复用已解析策略：

```rust
let engine = AdmissionEngine::from_json_str(policy_json)?;
let request = AdmissionRequest::from_json_str(request_json)?;
let report = engine.preflight(&request);
```

## 策略文档

根节点可以是策略数组，或包含 `policies` 数组的对象。示例见
`tests/fixtures/policies.json`。

```json
{
  "policies": [
    {
      "id": "desktop-release",
      "priority": 20,
      "product_lines": ["desktop-*"],
      "publisher_scope": {
        "include": ["acme.*"],
        "exclude": ["acme.legacy"]
      },
      "required_signatures": 2,
      "required_publishers": ["acme.release", "acme.security"],
      "require_distinct_publishers": true,
      "allowed_algorithms": ["sha256"],
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_until": "2027-01-01T00:00:00Z",
      "status": "active"
    }
  ]
}
```

字段说明：

- `id`：策略唯一标识，重复会导致 `SIG1002`。
- `priority`：策略链排序键，数值小的先出现；同优先级保持配置顺序。
- `product_lines`：产品线通配模式，支持 `*` 与 `?`；缺省视为 `*`。
- `publisher_scope.include`：允许的发布者模式；空数组表示不限制。
- `publisher_scope.exclude`：排除的发布者模式，始终优先于 include。
- `required_signatures`：至少需要的有效、去重签名数，缺省为 `1`。
- `required_publishers`：必须各有一个有效签名的发布者模式集合。
- `require_distinct_publishers`：为 `true` 时同一发布者只计一个有效签名。
- `allowed_algorithms`：允许的签名算法；空数组表示不限制。
- `valid_from` / `valid_until`：策略有效期，采用左闭右开区间。
- `status`：`active` 或 `revoked`；也可用 `revoked: true` 或 `revoked_at`。

兼容别名：`min_signatures`、`publishers`、`excluded_publishers`、`products` 等，
解析器同时接受扁平有效期字段和 `validity` 对象。

## 发布请求

```json
{
  "product_line": "desktop-stable",
  "publish_at": "2026-11-26T10:00:00Z",
  "artifact": {
    "path": "tests/fixtures/release.bin",
    "sha256": "4b327abf7a83b7602345c0b97378321c7fb3b4f0d61e49a186f806555e6cf1ff"
  },
  "signatures": [
    {
      "key_id": "release-key-1",
      "publisher": "acme.release",
      "algorithm": "sha256",
      "artifact_sha256": "4b327abf7a83b7602345c0b97378321c7fb3b4f0d61e49a186f806555e6cf1ff",
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_until": "2027-01-01T00:00:00Z",
      "status": "active"
    }
  ]
}
```

`artifact` 可以直接是 SHA-256 字符串，也可以指定仓库内夹具路径；指定路径时使用
`sha2` 计算摘要，并在文件可识别时用 `object` 提取格式与架构信息。签名的
`artifact_sha256` 必须与制品摘要一致。`publish_at` 接受 RFC3339 或 Unix 秒；
签名有效期同样按左闭右开区间判断。

签名撤销状态支持 `revoked: true`、`status: "revoked"`（或
`revocation_status: "revoked"`）以及 `revoked_at`。未来生效的 `revoked_at`
只会在到达该时间后拒绝。

## 评估与冲突规则

1. 仅产品线模式命中的策略进入策略链。
2. 策略按 `priority` 升序排列，同优先级保持配置顺序。
3. 每条策略独立检查撤销、有效期、发布者范围、算法、摘要绑定、签名有效期、
   去重发布者和必需发布者。
4. 策略满足门槛即允许；其他产品线的签名只会出现在该策略的签名证据中，不会
   单独造成拒绝。
5. 所有命中策略中任一为拒绝，最终为拒绝；全部允许且至少命中一条策略才允许。
6. 没有产品线策略命中时拒绝，错误码为 `SIG2001`，策略链为空。

策略链中每条记录包含 `policy_id`、`priority`、`decision`、`error_codes`、
`accepted_signatures`、`accepted_publishers` 和逐签名 `signature_findings`。
最终报告的 `error_codes` 按策略链顺序去重汇总。

## 稳定错误码

错误码是公开接口的一部分，后续版本不得改变其含义。

| 错误码 | 含义 |
| --- | --- |
| `SIG1001` | 策略 JSON 无效 |
| `SIG1002` | 必填字段缺失或类型/取值错误 |
| `SIG1003` | 时间格式或日历值无效 |
| `SIG1004` | 制品摘要不是 64 位十六进制 SHA-256 |
| `SIG1005` | 制品夹具读取失败 |
| `SIG1006` | 发布请求 JSON 无效 |
| `SIG1007` | 策略配置文件读取失败 |
| `SIG1008` | 发布请求文件读取失败 |
| `SIG2001` | 没有产品线策略命中 |
| `SIG2002` | 命中策略已撤销 |
| `SIG2003` | 命中策略不在有效期内 |
| `SIG3001` | 有效签名数量不足 |
| `SIG3002` | 发布者不在策略范围 |
| `SIG3003` | 签名不在有效期内 |
| `SIG3004` | 签名已撤销 |
| `SIG3005` | 签名未绑定到当前制品摘要 |
| `SIG3006` | 签名算法不被策略允许 |
| `SIG3007` | 重复签名者不能重复计数 |
| `SIG3008` | 缺少策略显式要求的发布者 |

## 测试夹具

所有测试只读取 `tests/fixtures/` 内的仓库夹具：

- `policies.json`：产品线策略、发布者范围、有效期和撤销配置。
- `request_allow.json`：多签名允许路径。
- `request_deny.json`：无签名拒绝路径。
- `release.bin`：SHA-256 制品绑定夹具。
- `minimal_elf.hex`：用于验证 `object` 格式/架构提取的仓库内 ELF 夹具。

测试覆盖策略链顺序、冲突从严、多签名、必需发布者、发布者排除、有效期、撤销、
摘要不匹配、无策略命中和 CLI 退出码。
