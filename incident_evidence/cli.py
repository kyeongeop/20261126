from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import Settings
from .evidence import create_evidence_package
from .signing import load_or_create_signing_material
from .verification import verify_package


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="incident-evidence")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser(
        "verify",
        help="verify a signed evidence package",
    )
    verify.add_argument("package", type=Path)
    verify.add_argument(
        "--public-key",
        type=Path,
        help="independently trusted Ed25519 public key (recommended)",
    )
    verify.add_argument("--json", action="store_true", help="emit JSON")

    export = subparsers.add_parser(
        "export",
        help="create a signed package for an incident already in SQLite",
    )
    export.add_argument("incident_id")
    export.add_argument("--exporter-name", required=True)
    export.add_argument("--exporter-email", default="")
    export.add_argument("--exporter-organization", default="")

    key_info = subparsers.add_parser(
        "key-info",
        help="show the active local signing public key",
    )
    key_info.add_argument("--json", action="store_true")

    serve = subparsers.add_parser("serve", help="run the FastAPI service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")
    return parser


def _verify(args: argparse.Namespace) -> int:
    result = verify_package(
        args.package,
        trusted_public_key=args.public_key,
    )
    payload = result.as_dict()
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print("VALID" if result.valid else "INVALID")
        print(f"package_sha256: {result.package_sha256}")
        if result.key_id:
            print(f"key_id: {result.key_id}")
        for check in result.checks:
            marker = "PASS" if check.passed else "FAIL"
            print(f"[{marker}] {check.name}: {check.detail}")
        for error in result.errors:
            print(f"ERROR: {error}", file=sys.stderr)
    return 0 if result.valid else 1


def _export(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    exporter = {
        "name": args.exporter_name,
        "email": args.exporter_email,
        "organization": args.exporter_organization,
    }
    package = create_evidence_package(settings, args.incident_id, exporter)
    print(json.dumps(package, ensure_ascii=False, indent=2))
    return 0


def _key_info(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    signing = load_or_create_signing_material(settings.signing_key_path)
    payload = {
        "key_id": signing.key_id,
        "public_key_sha256": signing.public_key_sha256,
        "public_key_path": str(settings.public_key_path.resolve()),
        "private_key_path": str(settings.signing_key_path.resolve()),
        "algorithm": "Ed25519",
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for key, value in payload.items():
            print(f"{key}: {value}")
    return 0


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "incident_evidence.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "verify":
        return _verify(args)
    if args.command == "export":
        return _export(args)
    if args.command == "key-info":
        return _key_info(args)
    if args.command == "serve":
        return _serve(args)
    raise AssertionError(f"unknown command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())

