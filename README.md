# 20261126

Repository initialized for 20261126.

## MFA 重置工作流（企业身份管理控制台）

员工丢失认证器后，系统不再提供“管理员直接清空 MFA 字段”的入口，
改为带审批的重置流程。实现位于 `mfa/` 包，可通过 `cmd/idconsole` 启动。

### 流程与规则

1. **提交申请**：用户本人提交重置申请，必须包含
   - 丢失原因 `reason`
   - 临时恢复窗口 `window_minutes`（1–120 分钟）
   - 通知方式 `notify_method`（`email` / `sms`，须已有对应联系方式）
   - 结束条件 `end_condition`（`window_expiry` 窗口到期结束 /
     `reenrollment` 重新注册后提前结束，两者到期后都必须重新注册）
2. **管理员审批**：仅管理员可批准或驳回；驳回必须填写说明，且不会下发任何凭证。
3. **恢复窗口**：批准后旧认证器因子立即挂起，系统通过所选通知方式下发
   一次性恢复令牌（仅存 SHA-256 哈希，令牌不经过 HTTP 响应返回）。
4. **访问限制**：窗口内仅可访问低敏感应用；访问高敏感应用一律拒绝
   （`high_sensitive_blocked`）。
5. **结束与重新注册**：窗口到期、管理员撤销或用户重新注册都会关闭窗口；
   窗口结束后必须重新注册认证器才能恢复正常访问。

所有状态转换写入内存审计流水（`request.submit`、`request.approve`、
`mfa.suspend`、`request.reject`、`request.expire`、`request.revoke`、
`request.reenroll`）。

### HTTP 接口

调用方通过 `X-Actor-Id` / `X-Actor-Role` 头标识已认证主体，
恢复令牌通过 `X-Recovery-Token` 头提交。

- `POST /mfa/reset-requests` 提交重置申请
- `GET  /mfa/reset-requests` 列出申请（管理员看全部，用户只看本人）
- `GET  /mfa/reset-requests/{id}` 查询申请详情
- `POST /mfa/reset-requests/{id}/approve` 管理员批准并打开恢复窗口
- `POST /mfa/reset-requests/{id}/reject` 管理员驳回
- `POST /mfa/reset-requests/{id}/revoke` 管理员提前撤销窗口
- `POST /mfa/reset-requests/{id}/reenroll` 凭恢复令牌重新注册、关闭窗口
- `POST /mfa/enroll` 窗口结束后重新注册认证器
- `POST /mfa/access-check` 应用访问决策（高敏感拦截）

### 技术约束

- Go 1.24（`go.mod` 声明，`go list -m all` 无第三方依赖）
- 仅使用标准库：HTTP 用 `net/http`，令牌/密钥用 `crypto/rand`、
  `crypto/sha256`，报文用 `encoding/json`
- 无外部数据库：存储为带 `sync.RWMutex` 的内存实现，时钟可注入以便测试
- 测试统一使用 `go test ./...`，无需任何外部服务
