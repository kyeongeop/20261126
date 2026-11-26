#!/usr/bin/env python3
"""Rebuild the repository fixtures with Python's standard library.

The Rust application never invokes this script; it only reads the generated
files below fixtures/.  Archives are deterministic so their SHA-256 values can
be pinned in the upload manifests.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PAYLOAD = ROOT / "payload"
ARCHIVES = ROOT / "archives"
DATE_TIME = (2026, 11, 26, 0, 0, 0)


def run(*args: str) -> None:
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def build_payload() -> None:
    if PAYLOAD.exists():
        shutil.rmtree(PAYLOAD)
    src = ROOT / "src"
    src.mkdir(parents=True, exist_ok=True)
    for directory in ("bin", "etc", "docs", "lib", "run", "scripts"):
        (PAYLOAD / directory).mkdir(parents=True, exist_ok=True)
    (src / "agent.c").write_text(
        "#include <stdio.h>\n"
        "int main(void){puts(\"agent 2.4.0\");return 0;}\n",
        encoding="utf-8",
    )
    (src / "lib.c").write_text(
        "int agent_status(void){return 0;}\n",
        encoding="utf-8",
    )
    (src / "updater.c").write_text(
        "#include <stdio.h>\n"
        "int main(void){puts(\"updater\");return 0;}\n",
        encoding="utf-8",
    )
    run("gcc", "-O2", "-s", "-o", str(PAYLOAD / "bin" / "agent"), str(src / "agent.c"))
    run(
        "gcc",
        "-O2",
        "-s",
        "-shared",
        "-fPIC",
        "-Wl,-soname,libagent.so.1",
        "-o",
        str(PAYLOAD / "lib" / "libagent.so.1"),
        str(src / "lib.c"),
    )
    run(
        "gcc",
        "-O2",
        "-s",
        "-o",
        str(PAYLOAD / "bin" / "updater"),
        str(src / "updater.c"),
    )
    shutil.copy2(PAYLOAD / "bin" / "agent", PAYLOAD / "bin" / "setuid-tool")
    shutil.copy2(PAYLOAD / "bin" / "agent", PAYLOAD / "bin" / "readonly-agent")
    write(PAYLOAD / "etc" / "agent.conf", b"mode = \"stable\"\n", 0o644)
    write(PAYLOAD / "etc" / "world.toml", b"debug = true\n", 0o666)
    write(PAYLOAD / "docs" / "README.md", b"# agent\n\nRelease 2.4.0\n", 0o644)
    write(PAYLOAD / "scripts" / "start.sh", b"#!/bin/sh\nexec ./bin/agent\n", 0o755)
    write(PAYLOAD / "run" / "agent", (PAYLOAD / "bin" / "agent").read_bytes(), 0o755)
    (PAYLOAD / "lib" / "libagent.so").symlink_to("libagent.so.1")
    (PAYLOAD / "bin" / "agent").chmod(0o755)
    (PAYLOAD / "bin" / "updater").chmod(0o755)
    (PAYLOAD / "bin" / "setuid-tool").chmod(0o4755)
    (PAYLOAD / "bin" / "readonly-agent").chmod(0o644)


def file_bytes(relative: str) -> bytes:
    return (PAYLOAD / relative).read_bytes()


def add_zip(
    archive: zipfile.ZipFile,
    name: str,
    data: bytes,
    mode: int,
    file_type: int = stat.S_IFREG,
) -> None:
    info = zipfile.ZipInfo(name, DATE_TIME)
    info.create_system = 3
    info.external_attr = (file_type | mode) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, data)


def clean_members(fix: bool = False) -> list[tuple[str, bytes, int, int]]:
    readme = b"# agent\n\nFixed release 2.4.0\n" if fix else file_bytes("docs/README.md")
    return [
        ("bin/", b"", 0o755, stat.S_IFDIR),
        ("bin/agent", file_bytes("bin/agent"), 0o755, stat.S_IFREG),
        ("bin/updater", file_bytes("bin/updater"), 0o755, stat.S_IFREG),
        ("docs/", b"", 0o755, stat.S_IFDIR),
        ("docs/README.md", readme, 0o644, stat.S_IFREG),
        ("etc/", b"", 0o755, stat.S_IFDIR),
        ("etc/agent.conf", file_bytes("etc/agent.conf"), 0o644, stat.S_IFREG),
        ("lib/", b"", 0o755, stat.S_IFDIR),
        ("lib/libagent.so.1", file_bytes("lib/libagent.so.1"), 0o755, stat.S_IFREG),
        ("lib/libagent.so", b"libagent.so.1", 0o777, stat.S_IFLNK),
        ("run/", b"", 0o755, stat.S_IFDIR),
        ("run/agent", file_bytes("run/agent"), 0o755, stat.S_IFREG),
        ("scripts/", b"", 0o755, stat.S_IFDIR),
        ("scripts/start.sh", file_bytes("scripts/start.sh"), 0o755, stat.S_IFREG),
    ]


def bad_members() -> list[tuple[str, bytes, int, int]]:
    members = clean_members()
    members.extend(
        [
            ("/etc/shadow", b"root:*:0:0:root:/root:/bin/sh\n", 0o644, stat.S_IFREG),
            ("../../etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n", 0o644, stat.S_IFREG),
            ("bin/agent", b"duplicate member\n", 0o755, stat.S_IFREG),
            ("bin/setuid-tool", file_bytes("bin/setuid-tool"), 0o4755, stat.S_IFREG),
            ("bin/setgid-tool", file_bytes("bin/agent"), 0o2755, stat.S_IFREG),
            ("bin/readonly-agent", file_bytes("bin/readonly-agent"), 0o644, stat.S_IFREG),
            ("bin\\win-agent", b"echo windows-path\n", 0o644, stat.S_IFREG),
            ("Bin/Agent", file_bytes("bin/agent"), 0o755, stat.S_IFREG),
            ("bin/agent/extra", b"prefix conflict\n", 0o644, stat.S_IFREG),
            ("etc/world.toml", file_bytes("etc/world.toml"), 0o666, stat.S_IFREG),
            ("lib/absolute.so", b"/etc/ld.so.preload", 0o777, stat.S_IFLNK),
            ("lib/escaping.so", b"../../../etc/passwd", 0o777, stat.S_IFLNK),
            ("lib/loop-a", b"loop-b", 0o777, stat.S_IFLNK),
            ("lib/loop-b", b"loop-a", 0o777, stat.S_IFLNK),
            ("dev/null", b"", 0o666, stat.S_IFCHR),
            ("tmp/", b"", 0o777, stat.S_IFDIR),
            ("run/tool", file_bytes("run/agent"), 0o777, stat.S_IFREG),
        ]
    )
    return members


def write_zip(path: Path, members: list[tuple[str, bytes, int, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        for name, data, mode, file_type in members:
            add_zip(archive, name, data, mode, file_type)


def tar_bytes(
    members: list[tuple[str, bytes, int, int]],
    hardlinks: list[tuple[str, str, int]] | None = None,
) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data, mode, file_type in members:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            if file_type == stat.S_IFDIR:
                info.type = tarfile.DIRTYPE
                info.size = 0
                archive.addfile(info)
            elif file_type == stat.S_IFLNK:
                info.type = tarfile.SYMTYPE
                info.linkname = data.decode("utf-8")
                info.size = 0
                archive.addfile(info)
            elif file_type == stat.S_IFCHR:
                info.type = tarfile.CHRTYPE
                info.size = 0
                archive.addfile(info)
            else:
                info.type = tarfile.REGTYPE
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        for name, target, mode in hardlinks or []:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.type = tarfile.LNKTYPE
            info.linkname = target
            archive.addfile(info)
    return buffer.getvalue()


def write_tar(
    path: Path,
    members: list[tuple[str, bytes, int, int]],
    gz: bool,
    hardlinks: list[tuple[str, str, int]] | None = None,
) -> None:
    payload = tar_bytes(members, hardlinks)
    path.parent.mkdir(parents=True, exist_ok=True)
    if gz:
        path.write_bytes(gzip.compress(payload, mtime=0))
    else:
        path.write_bytes(payload)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_manifest(path: Path, manifest: dict) -> None:
    path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def build_archives() -> None:
    if ARCHIVES.exists():
        shutil.rmtree(ARCHIVES)
    ARCHIVES.mkdir(parents=True)
    clean = clean_members()
    fixed = clean_members(fix=True)
    bad = bad_members()
    clean_zip = ARCHIVES / "agent-2.4.0.zip"
    fix_zip = ARCHIVES / "agent-2.4.0-fix.zip"
    bad_zip = ARCHIVES / "agent-2.4.1-bad.zip"
    clean_tgz = ARCHIVES / "agent-2.4.0.tar.gz"
    bad_tar = ARCHIVES / "agent-2.4.1-bad.tar"
    write_zip(clean_zip, clean)
    write_zip(fix_zip, fixed)
    write_zip(bad_zip, bad)
    write_tar(clean_tgz, clean, True, [("bin/agent-hard", "bin/agent", 0o755)])
    write_tar(
        bad_tar,
        bad,
        False,
        [
            ("bin/agent-hard", "../../etc/passwd", 0o755),
            ("bin/missing-hard", "bin/missing", 0o644),
        ],
    )

    write_manifest(
        ROOT / "upload.json",
        {
            "schema_version": 1,
            "release": {"name": "agent", "version": "2.4.0", "build": "release-1"},
            "archive": {"path": "archives/agent-2.4.0.zip", "sha256": digest(clean_zip)},
        },
    )
    write_manifest(
        ROOT / "upload-tar.json",
        {
            "schema_version": 1,
            "release": {"name": "agent", "version": "2.4.0", "build": "release-tar"},
            "archive": {"path": "archives/agent-2.4.0.tar.gz", "sha256": digest(clean_tgz)},
        },
    )
    write_manifest(
        ROOT / "upload-bad.json",
        {
            "schema_version": 1,
            "release": {"name": "agent", "version": "2.4.1", "build": "bad"},
            "archive": {"path": "archives/agent-2.4.1-bad.zip", "sha256": digest(bad_zip)},
        },
    )
    write_manifest(
        ROOT / "upload-bad-tar.json",
        {
            "schema_version": 1,
            "release": {"name": "agent", "version": "2.4.1", "build": "bad-tar"},
            "archive": {"path": "archives/agent-2.4.1-bad.tar", "sha256": digest(bad_tar)},
        },
    )
    write_manifest(
        ROOT / "reupload.json",
        {
            "schema_version": 1,
            "release": {"name": "agent", "version": "2.4.0", "build": "release-2"},
            "upload_type": "fix",
            "archive": {"path": "archives/agent-2.4.0-fix.zip", "sha256": digest(fix_zip)},
            "previous": {
                "path": "archives/agent-2.4.0.zip",
                "sha256": digest(clean_zip),
            },
        },
    )
    write_manifest(
        ROOT / "reupload-regression.json",
        {
            "schema_version": 1,
            "release": {"name": "agent", "version": "2.4.1", "build": "fix-regression"},
            "upload_type": "fix",
            "archive": {"path": "archives/agent-2.4.1-bad.zip", "sha256": digest(bad_zip)},
            "previous": {
                "path": "archives/agent-2.4.0.zip",
                "sha256": digest(clean_zip),
            },
        },
    )


def main() -> None:
    build_payload()
    build_archives()
    print("fixtures rebuilt")


if __name__ == "__main__":
    main()
