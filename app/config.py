"""Application configuration resolved from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    base_dir: Path
    source_dir: Path
    db_path: Path

    @classmethod
    def from_env(cls) -> "Settings":
        base_dir = Path(
            os.environ.get("APP_BASE_DIR", Path.cwd())
        ).resolve()
        source_dir = Path(
            os.environ.get("APP_SOURCE_DIR", base_dir / "data" / "sources")
        ).resolve()
        db_path = Path(
            os.environ.get("APP_DB_PATH", base_dir / "data" / "timeline.db")
        ).resolve()
        return cls(base_dir=base_dir, source_dir=source_dir, db_path=db_path)
