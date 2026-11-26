#!/usr/bin/env bash
# Reproduce the in-repo ELF/ar fixtures. The gate and its tests only READ the
# resulting files under fixtures/; this script is documentation/tooling.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/fixtures/src"
BIN="$ROOT/fixtures/bin"
LIB="$ROOT/fixtures/lib"
STA="$ROOT/fixtures/static"
OTH="$ROOT/fixtures/other"
mkdir -p "$BIN" "$LIB" "$STA" "$OTH"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Hardened PIE executable vs. deliberately weak ET_EXEC.
gcc -O2 -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
  "$SRC/app.c" -o "$BIN/app_hardened"
gcc -O0 -fno-pie -no-pie -fno-stack-protector -U_FORTIFY_SOURCE \
  -Wl,-z,norelro -Wl,-z,lazy -Wl,-z,execstack \
  "$SRC/app.c" -o "$BIN/app_weak"

# Hardened vs. weak shared objects.
gcc -O2 -fPIC -shared -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -Wl,-soname,libmgate_hard.so.1 -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
  "$SRC/shlib.c" -o "$LIB/libmgate_hard.so"
gcc -O0 -fPIC -shared -fno-stack-protector -U_FORTIFY_SOURCE \
  -Wl,-soname,libmgate_weak.so.1 -Wl,-z,norelro -Wl,-z,lazy -Wl,-z,execstack \
  "$SRC/shlib.c" -o "$LIB/libmgate_weak.so"

# Static archives: one with stack-canary evidence, one plain, one empty.
gcc -O2 -fstack-protector-strong -c "$SRC/staticlib.c" -o "$WORK/safe.o"
ar rcs "$STA/libmgate_safe.a" "$WORK/safe.o"
gcc -O0 -fno-stack-protector -c "$SRC/staticlib.c" -o "$WORK/plain.o"
ar rcs "$STA/libmgate_plain.a" "$WORK/plain.o"
ar rc  "$STA/libmgate_empty.a"

# Indeterminate / non-binary fixtures.
head -c 96 "$BIN/app_hardened" > "$OTH/truncated.elf"
printf 'not an elf artifact, just release notes\nmgate-fixture\n' > "$OTH/notes.txt"

echo "fixtures rebuilt under $ROOT/fixtures"
