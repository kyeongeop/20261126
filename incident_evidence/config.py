from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path
    db_path: Path
    signing_key_path: Path
    max_upload_bytes: int = 100 * 1024 * 1024

    @property
    def public_key_path(self) -> Path:
        return self.signing_key_path.with_suffix(".pub.pem")

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def packages_dir(self) -> Path:
        return self.data_dir / "packages"

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(os.environ.get("INCIDENT_DATA_DIR", "./data")).resolve()
        key_value = os.environ.get("EVIDENCE_SIGNING_KEY")
        signing_key_path = (
            Path(key_value).expanduser().resolve()
            if key_value
            else data_dir / "keys" / "evidence-signing-key.pem"
        )
        max_upload_bytes = int(
            os.environ.get("MAX_UPLOAD_BYTES", str(100 * 1024 * 1024))
        )
        return cls(
            data_dir=data_dir,
            db_path=data_dir / "incidents.sqlite3",
            signing_key_path=signing_key_path,
            max_upload_bytes=max_upload_bytes,
        )

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.signing_key_path.parent.mkdir(parents=True, exist_ok=True)
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.packages_dir.mkdir(parents=True, exist_ok=True)

