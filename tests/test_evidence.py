from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from incident_evidence.verification import verify_package

ROOT = Path(__file__).resolve().parents[1]


def _manifest(package: Path) -> dict:
    with zipfile.ZipFile(package) as archive:
        return json.loads(archive.read("manifest.json"))


def _rewrite_zip(
    source: Path,
    destination: Path,
    *,
    replacements: dict[str, bytes] | None = None,
    additions: dict[str, bytes] | None = None,
    removals: set[str] | None = None,
) -> None:
    replacements = replacements or {}
    additions = additions or {}
    removals = removals or set()
    with (
        zipfile.ZipFile(source) as original,
        zipfile.ZipFile(
            destination, "w", compression=zipfile.ZIP_DEFLATED
        ) as rewritten,
    ):
        for name in original.namelist():
            if name in removals:
                continue
            payload = replacements.get(name, original.read(name))
            rewritten.writestr(name, payload)
        for name, payload in additions.items():
            rewritten.writestr(name, payload)


def test_package_contents(exported: dict) -> None:
    metadata = exported["metadata"]
    package = exported["path"]
    assert package.is_file()
    assert metadata["sha256"]
    assert "--public-key" in metadata["verification"]["command"]

    with zipfile.ZipFile(package) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("manifest.json"))
        timeline = json.loads(archive.read("timeline.json"))
        source_config = json.loads(archive.read("source_config.json"))
        exporter = json.loads(archive.read("exporter.json"))
        checksums = archive.read("checksums.sha256").decode("utf-8")

    assert {
        "manifest.json",
        "signature.json",
        "public_key.pem",
        "timeline.json",
        "timeline.csv",
        "source_config.json",
        "exporter.json",
        "raw-files.json",
        "checksums.sha256",
        "VERIFY.md",
    } <= names
    assert len(manifest["timeline"]) == 3
    assert timeline["events"] == manifest["timeline"]
    assert source_config == exported["seeded"]["sample"]["source_config"]
    assert exporter == exported["seeded"]["sample"]["exporter"]
    assert len(manifest["raw_files"]) == 2
    assert all(entry["path"].startswith("raw/") for entry in manifest["raw_files"])
    assert all(entry["path"] in names for entry in manifest["raw_files"])
    assert all(
        entry["sha256"] in checksums
        for entry in manifest["checksums"]
        if entry["path"] != "checksums.sha256"
    )
    assert manifest["signing"]["algorithm"] == "Ed25519"


def test_valid_package_and_cli_verification(exported: dict) -> None:
    result = verify_package(
        exported["path"],
        trusted_public_key=exported["public_key"],
    )
    assert result.valid, result.errors
    assert all(check.passed for check in result.checks)

    completed = subprocess.run(
        exported["metadata"]["verification"]["command"],
        cwd=ROOT,
        shell=True,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "VALID" in completed.stdout


def test_replaced_raw_file_fails(exported: dict, tmp_path: Path) -> None:
    manifest = _manifest(exported["path"])
    raw_path = manifest["raw_files"][0]["path"]
    with zipfile.ZipFile(exported["path"]) as archive:
        original = archive.read(raw_path)
    same_size_replacement = b"X" + original[1:]
    assert len(same_size_replacement) == len(original)
    tampered = tmp_path / "tampered.zip"
    _rewrite_zip(
        exported["path"],
        tampered,
        replacements={raw_path: same_size_replacement},
    )
    result = verify_package(
        tampered,
        trusted_public_key=exported["public_key"],
    )
    assert not result.valid
    assert any(raw_path in error for error in result.errors)

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "incident_evidence.cli",
            "verify",
            str(tampered),
            "--public-key",
            str(exported["public_key"]),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 1
    assert "INVALID" in completed.stdout


@pytest.mark.parametrize(
    "target",
    [
        "manifest.json",
        "timeline.json",
        "source_config.json",
        "public_key.pem",
        "checksums.sha256",
    ],
)
def test_replaced_signed_metadata_fails(
    exported: dict,
    tmp_path: Path,
    target: str,
) -> None:
    with zipfile.ZipFile(exported["path"]) as archive:
        payload = archive.read(target)
    replacement = payload + b"\n"
    tampered = tmp_path / f"tampered-{target}.zip"
    _rewrite_zip(
        exported["path"],
        tampered,
        replacements={target: replacement},
    )
    result = verify_package(
        tampered,
        trusted_public_key=exported["public_key"],
    )
    assert not result.valid


def test_replaced_signature_fails(exported: dict, tmp_path: Path) -> None:
    tampered = tmp_path / "signature-replaced.zip"
    _rewrite_zip(
        exported["path"],
        tampered,
        replacements={"signature.json": b"{}"},
    )
    result = verify_package(
        tampered,
        trusted_public_key=exported["public_key"],
    )
    assert not result.valid

    with zipfile.ZipFile(exported["path"]) as archive:
        signature = archive.read("signature.json")
    whitespace_tampered = tmp_path / "signature-appended.zip"
    _rewrite_zip(
        exported["path"],
        whitespace_tampered,
        replacements={"signature.json": signature + b"\n"},
    )
    result = verify_package(
        whitespace_tampered,
        trusted_public_key=exported["public_key"],
    )
    assert not result.valid
    assert any("canonical" in error for error in result.errors)


def test_added_unsigned_file_fails(exported: dict, tmp_path: Path) -> None:
    tampered = tmp_path / "with-extra.zip"
    _rewrite_zip(
        exported["path"],
        tampered,
        additions={"notes.txt": b"unsigned note\n"},
    )
    result = verify_package(
        tampered,
        trusted_public_key=exported["public_key"],
    )
    assert not result.valid
    assert any("extra" in error for error in result.errors)


def test_invalid_public_key_fails_cleanly(exported: dict, tmp_path: Path) -> None:
    tampered = tmp_path / "bad-public-key.zip"
    _rewrite_zip(
        exported["path"],
        tampered,
        replacements={"public_key.pem": b"not a pem key"},
    )
    result = verify_package(
        tampered,
        trusted_public_key=exported["public_key"],
    )
    assert not result.valid
    assert any("valid Ed25519 public key" in error for error in result.errors)


def test_missing_file_fails(exported: dict, tmp_path: Path) -> None:
    manifest = _manifest(exported["path"])
    raw_path = manifest["raw_files"][0]["path"]
    tampered = tmp_path / "missing-raw.zip"
    _rewrite_zip(
        exported["path"],
        tampered,
        removals={raw_path},
    )
    result = verify_package(
        tampered,
        trusted_public_key=exported["public_key"],
    )
    assert not result.valid
    assert any("missing" in error for error in result.errors)


def test_untrusted_public_key_fails(exported: dict, tmp_path: Path) -> None:
    other_key = Ed25519PrivateKey.generate().public_key()
    wrong_key = tmp_path / "wrong-public-key.pem"
    wrong_key.write_bytes(
        other_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    result = verify_package(
        exported["path"],
        trusted_public_key=wrong_key,
    )
    assert not result.valid
    assert any("trusted public key" in error for error in result.errors)


def test_source_mutation_blocks_export(
    client: TestClient,
    settings,
    seeded: dict,
) -> None:
    incident_id = seeded["incident"]["id"]
    files = client.get(f"/api/incidents/{incident_id}/raw-files").json()
    stored = next(
        (settings.data_dir / "uploads" / incident_id).glob(
            f"*{Path(files[0]['original_name']).name}"
        )
    )
    stored.write_bytes(b"mutated after ingestion\n")

    response = client.post(
        f"/api/incidents/{incident_id}/evidence-packages",
        json={"exporter": seeded["sample"]["exporter"]},
    )
    assert response.status_code == 409
    assert "changed after ingestion" in response.json()["detail"]


def test_export_missing_incident_returns_404(client: TestClient) -> None:
    response = client.post(
        "/api/incidents/inc_missing/evidence-packages",
        json={"exporter": {"name": "Alice"}},
    )
    assert response.status_code == 404


def test_online_verification_endpoint(
    client: TestClient,
    exported: dict,
) -> None:
    with exported["path"].open("rb") as package:
        response = client.post(
            "/api/evidence-packages/verify",
            files={
                "package": ("evidence.zip", package, "application/zip"),
                "public_key": (
                    "evidence-signing-key.pub.pem",
                    exported["public_key"].read_bytes(),
                    "application/x-pem-file",
                ),
            },
        )
    assert response.status_code == 200, response.text
    assert response.json()["valid"] is True

