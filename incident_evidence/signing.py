from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True, slots=True)
class SigningMaterial:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    key_id: str
    public_key_pem: bytes
    public_key_sha256: str


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def key_id_for(public_key: Ed25519PublicKey) -> str:
    return public_key_fingerprint(public_key)[:32]


def public_key_pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_or_create_signing_material(key_path: Path) -> SigningMaterial:
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if not key_path.exists():
        private_key = Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        try:
            descriptor = os.open(
                key_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(pem)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(key_path, 0o600)

    loaded = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError(f"signing key at {key_path} is not an Ed25519 private key")

    public_key = loaded.public_key()
    pem = public_key_pem(public_key)
    public_path = key_path.with_suffix(".pub.pem")
    if not public_path.exists() or public_path.read_bytes() != pem:
        public_path.write_bytes(pem)
        os.chmod(public_path, 0o644)

    return SigningMaterial(
        private_key=loaded,
        public_key=public_key,
        key_id=key_id_for(public_key),
        public_key_pem=pem,
        public_key_sha256=public_key_fingerprint(public_key),
    )


def load_public_key(path: Path) -> Ed25519PublicKey:
    loaded = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError(f"public key at {path} is not an Ed25519 public key")
    return loaded


def load_public_key_bytes(payload: bytes) -> Ed25519PublicKey:
    loaded = serialization.load_pem_public_key(payload)
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("trusted key is not an Ed25519 public key")
    return loaded


def sign_bytes(private_key: Ed25519PrivateKey, payload: bytes) -> bytes:
    return private_key.sign(payload)


def verify_bytes(
    public_key: Ed25519PublicKey,
    signature: bytes,
    payload: bytes,
) -> bool:
    try:
        public_key.verify(signature, payload)
        return True
    except InvalidSignature:
        return False


def encode_signature(signature: bytes) -> str:
    return base64.b64encode(signature).decode("ascii")


def decode_signature(value: str) -> bytes:
    return base64.b64decode(value, validate=True)

