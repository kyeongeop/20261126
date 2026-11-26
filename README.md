# 20261126

Repository initialized for 20261126.

## Internal Package Registry

Go 1.24 implementation using only `net/http`, `archive/tar` and
`crypto/sha256`. All state (tokens, packages, audit log) lives as
files under the data directory — no cloud services.

### Run

```sh
REGISTRY_ADMIN_TOKEN=choose-a-strong-admin-token \
  go run ./cmd/registry -addr 127.0.0.1:8080 -data ./data
```

### Scoped tokens

Tokens replace the old all-namespaces publish token. Each token is bound to:

- **actions** — explicit list from `read`, `publish`, `revoke`; or a
  **purpose** preset: `readonly`, `publish`, `revoke`
- **namespace_prefix** — e.g. `acme/`; required, tokens are never global
- **package_pattern** — optional `path.Match` glob on `namespace/name`,
  e.g. `acme/billing-*`

The secret is returned once at creation; only its sha256 hash is stored.

```sh
# mint a read-only CI token for acme/billing-*
curl -X POST $REG/v1/admin/tokens -H "Authorization: Bearer $ADMIN" -d '{
  "label": "ci-read", "purpose": "readonly",
  "namespace_prefix": "acme/", "package_pattern": "acme/billing-*"
}'

# publish / fetch / revoke
curl -X PUT  --data-binary @pkg.tar -H "Authorization: Bearer $TOK" \
  $REG/v1/packages/acme/billing-api/1.0.0
curl -H "Authorization: Bearer $TOK" $REG/v1/packages/acme/billing-api/1.0.0
curl -X POST -H "Authorization: Bearer $TOK" \
  "$REG/v1/packages/acme/billing-api/1.0.0/revoke?reason=bad-build"
```

### Audit and error uniformity

- Every decision — allow **and** deny — is appended to
  `data/audit.log` as a sha256 hash-chained JSONL record
  (`audit.Verify` detects tampering).
- Missing token, invalid token, out-of-scope namespace/package and
  nonexistent package all return the identical
  `404 {"error":"not found"}`, so responses never reveal whether other
  namespace prefixes exist. The real reason is only in the audit log.

### Test

```sh
go test ./...
```
