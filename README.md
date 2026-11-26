# 内部不可变签名软件包仓库

单个 Go 1.24 服务进程、仅使用标准库实现的内部 tar 软件包仓库。发布成功后，包名与版本号组合永久冻结；上传、管理员修复和下载验证都围绕同一份已签名发布记录完成。

## 核心保证

- **版本不可变**：发布元数据以硬链接 `O_EXCL` 方式落盘，重复的 `包名 + 版本号` 返回 `409 Conflict`，不存在覆盖更新接口。
- **内容摘要**：上传的 tar 原始字节经 `crypto/sha256` 计算为 `sha256:<hex>`，归档按摘要存入内容寻址对象目录。
- **签名元数据**：服务对发布记录（包名、版本、摘要、归档信息、发布者、修复关系、发布时间）做 HMAC-SHA256 签名。
- **发布者记录**：签名载荷包含上传者用户名、角色、发布时间和来源地址。
- **管理员修复**：管理员只能创建带 `repair_of` 关系的新版本；不能通过普通上传发布版本，也不能改写原版本。
- **下载验证**：下载页验证签名并重新计算归档摘要，分别显示签名和摘要状态；验证失败时禁用并拒绝下载。

## 运行

```bash
go run .
# 默认监听 127.0.0.1:8080，数据写入 ./data
```

可用参数和环境变量：

```bash
go run . -addr 0.0.0.0:8080 -data /var/lib/package-repository
PKG_ADDR=127.0.0.1:8080
PKG_DATA_DIR=./data
```

默认演示账号仅用于本机试用，部署时必须通过 `PKG_USERS` 覆盖：

```bash
PKG_USERS='publisher:strong-password:publisher,admin:another-password:admin' go run .
```

格式为 `用户名:密码:角色`，多个账号用逗号分隔；角色只能是 `publisher` 或 `admin`。若服务位于可信反向代理之后，可设置 `PKG_TRUST_IDENTITY_HEADERS=1`，从 `X-Authenticated-User` 和 `X-Authenticated-Role` 读取身份。

## 页面

- `/`：全部发布版本及签名验证状态。
- `/publish`：发布者上传新版本。
- `/admin/repair`：管理员创建修复版本。
- `/packages/{name}/{version}`：发布记录、发布者、签名和验证状态。
- `/packages/{name}/{version}/download`：仅在签名和摘要均通过时返回 tar。
- `/packages/{name}/{version}/manifest.json`：不可变签名清单。

## API

### 上传新版本

```bash
curl -u publisher:publisher-pass \
  -F name=tool \
  -F version=1.0.0 \
  -F package=@tool-1.0.0.tar \
  http://127.0.0.1:8080/api/packages
```

也可使用路径形式 `POST /api/packages/tool/1.0.0`，或直接把 tar 作为请求体并提供 `X-Package-Name`、`X-Package-Version` 头。成功返回 `201 Created`，响应包含发布记录和 `server_verification`。同版本再次上传返回 `409`、错误码 `version_exists`。

### 管理员修复

```bash
curl -u admin:admin-pass \
  -F replaces=1.0.0 \
  -F reason='修复启动脚本' \
  -F package=@tool-1.0.1.tar \
  http://127.0.0.1:8080/api/packages/tool/1.0.1/repair
```

`1.0.1` 是新修复版本，`replaces` 必须指向已存在版本。管理员对普通上传接口发起无修复关系的请求会返回 `403 admin_repair_only`。

### 验证

```bash
curl http://127.0.0.1:8080/api/packages/tool/1.0.0/verification
```

返回 `signature_valid`、`digest_valid`、`valid`、声明摘要和实际摘要。manifest 与下载响应还包含 `X-Signature-Verification` 和 `X-Content-SHA256` 头。

## 存储布局

```text
data/
  signing.key                  # 0600，服务持久签名密钥
  objects/<sha256>.tar         # 内容寻址的原始 tar
  releases/<name>/<version>.json
  tmp/
```

发布流程先写入临时文件并计算摘要，然后安装内容对象，最后以不覆盖方式创建发布元数据。所有元数据写入串行化，跨请求和并发上传也不能改写已存在的版本。

## 测试

```bash
go test ./...
go test -race ./...
```

测试覆盖摘要与签名生成、重复版本冲突、管理员修复边界、原始/multipart 上传、元数据篡改、归档篡改和下载拒绝。
