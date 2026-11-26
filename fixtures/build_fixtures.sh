#!/usr/bin/env bash
# 重新生成 fixtures/bin 下的 ELF 夹具。
# 制品随仓库提交；仅在需要重建时于 Linux + gcc 环境执行本脚本。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/bin"
LIB="$HERE/lib"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$BIN" "$LIB" "$LIB/sub"

# --- 底层库 libbase.so：无特殊路径，RUNPATH 指向同目录 ---
cat > "$TMP/base.c" <<'EOF'
int base_value(void) { return 42; }
EOF
gcc -shared -fPIC -Wl,-soname,libbase.so.1 \
    -Wl,--enable-new-dtags,-rpath,'$ORIGIN' "$TMP/base.c" \
    -o "$LIB/libbase.so.1"

# --- 中间库 libmiddle.so：依赖 libbase.so.1，使用 RUNPATH=$ORIGIN ---
cat > "$TMP/middle.c" <<'EOF'
extern int base_value(void);
int middle_value(void) { return base_value() + 1; }
EOF
gcc -shared -fPIC -Wl,-soname,libmiddle.so.1 \
    -Wl,--enable-new-dtags,-rpath,'$ORIGIN' "$TMP/middle.c" \
    -L"$LIB" -l:libbase.so.1 \
    -o "$LIB/libmiddle.so.1"

# --- 主程序 app：旧版 DT_RPATH，包含空路径项与 $ORIGIN 展开，多级依赖入口 ---
cat > "$TMP/app.c" <<'EOF'
extern int middle_value(void);
int main(void) { return middle_value() == 43 ? 0 : 1; }
EOF
gcc -fPIE -pie "$TMP/app.c" '-Wl,--disable-new-dtags,-rpath,:$ORIGIN/../lib/sub:$ORIGIN/../lib:$ORIGIN/../../../outside' \
    -L"$LIB" -l:libmiddle.so.1 -l:libbase.so.1 \
    -o "$BIN/app"

# --- 可执行文件 app_runpath：仅 DT_RUNPATH，含未展开变量 ${PLATFORM} ---
cat > "$TMP/runpath_app.c" <<'EOF'
extern int base_value(void);
int main(void) { return base_value() == 42 ? 0 : 1; }
EOF
gcc -fPIE -pie "$TMP/runpath_app.c" -Wl,--enable-new-dtags,-rpath,'$ORIGIN/../lib/${PLATFORM}' \
    -L"$LIB" -Wl,--no-as-needed -l:libbase.so.1 \
    -o "$BIN/app_runpath"

# --- 遮蔽库：同名 libbase.so.1 的另一份拷贝，位于子目录，触发版本遮蔽面板数据 ---
cp "$LIB/libbase.so.1" "$LIB/sub/libbase.so.1"

# --- strip 制品：移除节区表，仅保留程序头，验证 PT_DYNAMIC 回退解析 ---
cp "$LIB/libmiddle.so.1" "$LIB/libmiddle.stripped.so.1"
strip --strip-all "$LIB/libmiddle.stripped.so.1"

# --- 无节区表制品：strip 后再删除节区头表，强制走 PT_DYNAMIC 回退解析 ---
cp "$LIB/libmiddle.so.1" "$LIB/libmiddle.nosection.so.1"
strip --strip-all "$LIB/libmiddle.nosection.so.1"
python3 - "$LIB/libmiddle.nosection.so.1" <<'PY'
import struct, sys
path = sys.argv[1]
with open(path, "r+b") as fh:
    ident = fh.read(16)
    assert ident[:4] == b"\x7fELF" and ident[4] == 2, "仅支持 ELF64"
    fh.seek(0)
    header = fh.read(64)
    # ELF64 头：e_shoff 位于偏移 40，e_shnum/e_shstrndx 位于 60/62
    fh.seek(40)
    fh.write(struct.pack("<Q", 0))
    fh.seek(60)
    fh.write(struct.pack("<HH", 0, 0))
PY

# --- 缺失依赖程序：NEEDED 指向仓库内不存在的 liblost.so.1（等长原地改写） ---
cat > "$TMP/ghost.c" <<'EOF'
int main(void) { return 0; }
EOF
gcc -fPIE -pie "$TMP/ghost.c" -Wl,--enable-new-dtags,-rpath,'$ORIGIN/../lib' \
    -Wl,--no-as-needed -L"$LIB" -l:libbase.so.1 \
    -o "$BIN/app_missing"
cp "$BIN/app_missing" "$TMP/app_missing.bak"
python3 - "$TMP/app_missing.bak" "$BIN/app_missing" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
data = bytearray(open(src, "rb").read())
needle = b"libbase.so.1"
replacement = b"liblost.so.1"
assert len(needle) == len(replacement)
idx = data.find(needle)
assert idx >= 0, "NEEDED string not found"
data[idx:idx + len(needle)] = replacement
open(dst, "wb").write(data)
PY

echo "fixtures rebuilt under $HERE"
