# 企业身份管理控制台：角色变更差异审批

这是一个仅使用 Go 标准库实现的内存版服务，面向“管理员编辑角色”场景：

- 保存前返回新增、移除和继承影响差异，而不只展示最终权限集合。
- 差异中含敏感动作时，变更进入待审批状态，不会立即修改角色。
- 必须由另一名管理员审批，请求人不能自审。
- 审批人可以只批准部分敏感动作；未批准的敏感新增被拒绝，未批准的敏感移除被保留。
- 所有变更请求保留原始差异、审批选择和最终应用结果，便于审计。
- 使用角色版本校验防止审批过期变更覆盖新版本。

运行环境为 Go 1.24，代码只依赖标准库，测试使用仓库内 JSON 夹具。

## 运行

```bash
go run ./cmd/server
```

默认监听 `:8080`，可通过 `ADDR` 覆盖：

```bash
ADDR=127.0.0.1:9090 go run ./cmd/server
```

验证：

```bash
go test ./...
go test -race ./...
```

## 身份约定

示例服务信任认证网关传入的管理员身份。写操作必须携带以下任一请求头：

```http
X-Admin-ID: alice
```

```http
Authorization: Bearer alice
```

请求体和 URL 参数不能声明或覆盖审批人身份。夹具管理员为 `alice`、`bob`、`carol`。

## 本地夹具

夹具位于 `internal/roleadmin/testdata/seed.json`，主要角色如下：

- `billing_admin`：直接拥有 `billing.invoice.read`，继承 `support_agent`。
- `support_agent`：直接拥有 `tickets.assign`、`tickets.escalate`，继承 `base_support`。
- `security_auditor`：直接拥有 `audit.read`、`users.read`。
- 敏感动作包括 `billing.invoice.write`、`roles.manage`、`secrets.read`、`tickets.escalate`、`users.delete`。

## API

| 方法与路径 | 用途 |
| --- | --- |
| `GET /healthz` | 健康检查 |
| `GET /api/roles` | 列出角色 |
| `GET /api/roles/{roleID}` | 获取角色当前版本 |
| `POST /api/roles/{roleID}/diff` | 保存前预览差异，也可用 `/preview` |
| `POST /api/roles/{roleID}/change-requests` | 提交变更，也可直接 `POST /api/roles/{roleID}` |
| `GET /api/change-requests` | 查询审批记录，支持 `role_id`、`status` 过滤 |
| `GET /api/change-requests/{id}` | 获取单条审批记录 |
| `POST /api/change-requests/{id}/decision` | 批准、部分批准或拒绝 |
| `POST /api/change-requests/{id}/approve` | 批准别名，自动设置 `decision=approve` |
| `POST /api/change-requests/{id}/reject` | 拒绝别名，自动设置 `decision=reject` |

### 1. 预览差异

```bash
curl -sS -X POST http://localhost:8080/api/roles/billing_admin/diff \
  -H 'Content-Type: application/json' \
  -H 'X-Admin-ID: alice' \
  -d '{
    "base_version": 4,
    "direct_permissions": [
      "billing.invoice.read",
      "billing.invoice.write",
      "reports.read"
    ],
    "parent_role_ids": ["support_agent", "security_auditor"]
  }'
```

响应中的关键字段：

- `diff.added` / `diff.removed`：最终有效权限的变化。
- `diff.inherited_impact.parents_added` / `parents_removed`：父角色变化。
- `diff.inherited_impact.added` / `removed`：由继承产生的权限变化，包含继承路径。
- `diff.summary.sensitive`：需要审批的敏感动作数量。
- `diff.requires_approval`：本次保存前是否必须进入审批。
- `diff.approval_items`：可逐项批准或拒绝的敏感动作。
- `proposed_role`：预览对应的拟保存角色。

`source` 可能为 `direct`、`inherited` 或 `direct+inherited`。字段仅在预览时计算，不持久化。

### 2. 提交保存

请求体与预览相同。服务会基于最新角色状态重新计算差异，不信任客户端展示的旧预览。

```bash
curl -sS -X POST http://localhost:8080/api/roles/billing_admin/change-requests \
  -H 'Content-Type: application/json' \
  -H 'X-Admin-ID: alice' \
  -d '{
    "base_version": 4,
    "direct_permissions": [
      "billing.invoice.read",
      "billing.invoice.write",
      "users.delete"
    ]
  }'
```

无敏感变化时，返回 `201` 且状态为 `applied`。含敏感变化时，状态为 `pending_approval`，角色版本不变。

### 3. 另一名管理员部分批准

```bash
curl -sS -X POST http://localhost:8080/api/change-requests/cr_xxx/decision \
  -H 'Content-Type: application/json' \
  -H 'X-Admin-ID: bob' \
  -d '{
    "decision": "approve",
    "approved_actions": ["billing.invoice.write"],
    "comment": "只批准发票写入"
  }'
```

也可传审批项 ID：

```json
{
  "decision": "approve",
  "approved_item_ids": ["added:billing.invoice.write"]
}
```

批准全部敏感动作：

```json
{
  "decision": "approve",
  "approve_all": true
}
```

部分批准后的应用规则：

- 非敏感变化随审批一起应用。
- 已选中的敏感新增/移除按预期应用。
- 未选中的敏感新增不会生效；若来自继承，则写入 `excluded_permissions`。
- 未选中的敏感移除继续保留；必要时物化为直接权限。
- 响应中 `approval.partial=true`，`approved_item_ids`、`approved_actions` 和 `rejected_actions` 记录逐项结果。

拒绝示例：

```bash
curl -sS -X POST http://localhost:8080/api/change-requests/cr_xxx/decision \
  -H 'Content-Type: application/json' \
  -H 'X-Admin-ID: bob' \
  -d '{"decision":"reject","comment":"需要单独的安全评审"}'
```

## 错误与并发

错误统一返回：

```json
{
  "error": {
    "code": "role_version_changed",
    "message": "role billing_admin changed from version 4 to 5 after this request was created"
  }
}
```

常见状态码：

- `400`：非法 JSON、非法决策或未知审批项。
- `401` / `403`：缺少管理员身份、管理员不存在或请求人自审。
- `404`：角色或审批记录不存在。
- `409`：角色版本冲突，或审批记录已处理。
- `422`：继承循环、未知父角色或非法角色输入。

`excluded_permissions` 由部分批准自动维护，也会在角色响应中返回。显式清空它可能使被排除的敏感权限重新生效，因此同样会进入差异和审批流程。
