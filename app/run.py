"""Manual entry point: ``python -m app.run`` serves the API with uvicorn."""

from __future__ import annotations

import uvicorn

from .config import Settings
from .main import create_app


def main() -> None:
    settings = Settings.from_env()
    app = create_app(settings)
    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
