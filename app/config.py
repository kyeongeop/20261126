"""Application configuration.

All values can be overridden with environment variables so tests and
deployments do not have to edit the source tree.
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# SQLite database location. Defaults to a file under ``data/``; tests and
# ephemeral runs can point ``TIMELINE_DB`` at a temporary file.
DATABASE_PATH: str = os.environ.get(
    "TIMELINE_DB", str(BASE_DIR / "data" / "timeline.db")
)

# Maximum time spread (hours) used when auto-detecting merge candidates.
MERGE_WINDOW_HOURS: float = float(os.environ.get("MERGE_WINDOW_HOURS", "24"))

# Seed demo data on startup for the default application. Set
# ``TIMELINE_AUTO_SEED=0`` to disable. The application factory takes an
# explicit ``seed`` argument, so this only affects ``app.main:app``.
AUTO_SEED: bool = os.environ.get("TIMELINE_AUTO_SEED", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
    "",
}

DEFAULT_INCIDENT_ID = "INC-2026-1126"
