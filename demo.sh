#!/usr/bin/env bash
# 删除冷静期端到端演示：申请 -> 影响清单 -> 提前确认被拒 -> 同人确认被拒
# -> 第二人确认删除；以及“被引用包阻止完成”和“冷静期内撤回”。
set -u
cd "$(dirname "$0")"

PORT="${PORT:-18099}"
BASE="http://127.0.0.1:${PORT}"
COOLDOWN="${COOLDOWN:-3s}"
DATA="$(mktemp -d /tmp/pkgrepo-demo-XXXX)"
BIN="$(mktemp -u /tmp/pkgrepo-demo-bin-XXXX)"

echo ">> go build"
go build -o "$BIN" . || exit 1

PKG_ADDR="127.0.0.1:${PORT}" PKG_DATA_DIR="$DATA" PKG_DELETION_COOLDOWN="$COOLDOWN" "$BIN" &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  curl -sf "$BASE/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done

code() { curl -s -o /tmp/demo-body.json -w '%{http_code}' "$@"; }
id_of() { grep -oE '"id":"dr-[0-9]+"' /tmp/demo-body.json | head -1 | sed -E 's/.*"(dr-[0-9]+)".*/\1/'; }

echo
echo "== 1) 维护者申请删除 orphan-tool（无引用），进入冷静期 =="
c=$(code -u admin:admin-pass -X POST "$BASE/api/deletion-requests" \
  -H 'Content-Type: application/json' -d '{"name":"orphan-tool","reason":"obsolete demo"}')
ID=$(id_of); echo "HTTP $c  id=$ID  status=$(grep -oE '"status":"[a-z_]+"' /tmp/demo-body.json | head -1)"
echo "   影响: $(grep -oE '"download_count":[0-9]+' /tmp/demo-body.json | head -1) / $(grep -oE '"active_build_count":[0-9]+' /tmp/demo-body.json | head -1) (下载/进行中构建)"

echo
echo "== 2) 冷静期未到，另一管理员提前确认 -> 期望 409 =="
echo "HTTP $(code -u admin2:admin2-pass -X POST "$BASE/api/deletion-requests/$ID/confirm")  code=$(grep -oE '"code":"[a-z_]+"' /tmp/demo-body.json | head -1)"

echo ">> 等待冷静期 $COOLDOWN ..."; sleep 4

echo
echo "== 3) 申请人 admin 自己确认 -> 期望 403（必须另一个账号） =="
echo "HTTP $(code -u admin:admin-pass -X POST "$BASE/api/deletion-requests/$ID/confirm")  code=$(grep -oE '"code":"[a-z_]+"' /tmp/demo-body.json | head -1)"

echo
echo "== 4) 另一个管理员 admin2 确认 -> 期望 200 deleted =="
echo "HTTP $(code -u admin2:admin2-pass -X POST "$BASE/api/deletion-requests/$ID/confirm")  $(grep -oE '"status":"[a-z_]+"' /tmp/demo-body.json | head -1) by $(grep -oE '"confirmed_by":"[a-z0-9]+"' /tmp/demo-body.json | head -1)"
echo "   删除后取版本 -> HTTP $(code "$BASE/api/packages/orphan-tool/versions/1.0.0") (期望 404)"

echo
echo "== 5) 被引用的 core-utils：到期后第二人确认 -> 期望 409 package_referenced =="
c=$(code -u admin:admin-pass -X POST "$BASE/api/deletion-requests" -H 'Content-Type: application/json' -d '{"name":"core-utils"}')
RID=$(id_of); echo "HTTP $c id=$RID"
sleep 4
echo "HTTP $(code -u admin2:admin2-pass -X POST "$BASE/api/deletion-requests/$RID/confirm")  code=$(grep -oE '"code":"[a-z_]+"' /tmp/demo-body.json | head -1)  referrers=$(grep -oE '"referrer_count":[0-9]+' /tmp/demo-body.json | head -1)"

echo
echo "== 6) 冷静期内撤回 metrics-sdk -> 期望 withdrawn，包仍可访问 =="
c=$(code -u maintainer:maintainer-pass -X POST "$BASE/api/deletion-requests" -H 'Content-Type: application/json' -d '{"name":"metrics-sdk"}')
WID=$(id_of)
echo "create HTTP $c id=$WID ; withdraw HTTP $(code -u maintainer:maintainer-pass -X POST "$BASE/api/deletion-requests/$WID/withdraw") $(grep -oE '"status":"[a-z_]+"' /tmp/demo-body.json | head -1)"

echo
echo "演示完成。Web 控制台: $BASE/  (数据目录 $DATA)"
