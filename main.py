"""Root ASGI entry-point shim.

This lets ``uvicorn main:app`` work from the repository root in addition to
the canonical ``uvicorn app.main:app``.
"""

from app.main import app, create_app

__all__ = ["app", "create_app"]
