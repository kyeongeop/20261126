"""本地配置：仅环境变量覆盖，不依赖外部账号/服务。"""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "timeline.db"

DB_PATH = Path(os.environ.get("TIMELINE_DB_PATH", DEFAULT_DB_PATH))

DEFAULT_LIMIT = 100
MAX_LIMIT = 500
EXPORT_MAX_LIMIT = 5000
