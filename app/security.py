"""Authentication and role-based access control.

Clients authenticate with a static API token presented in the
``X-API-Token`` header (or ``Authorization: Bearer <token>``). Roles:

* ``admin``        - full access, incl. incident/event/evidence management.
* ``investigator`` - create events and evidence links; read everything.
* ``viewer``       - read-only access to incidents, events and evidence
  resolution, but never file bytes beyond the resolved snippet.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi import Header, HTTPException, status

from .database import get_user_by_token

ROLE_RANK = {"viewer": 1, "investigator": 2, "admin": 3}


@dataclass(frozen=True)
class Principal:
    username: str
    role: str

    def can_write(self) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK["investigator"]

    def can_admin(self) -> bool:
        return self.role == "admin"


def build_authenticator(db_path: Path):
    """Return a FastAPI dependency bound to a concrete database path."""

    def _authenticate(
        x_api_token: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> Principal:
        token = x_api_token
        if not token and authorization and authorization.lower().startswith(
            "bearer "
        ):
            token = authorization.split(" ", 1)[1].strip()
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing API token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        row = get_user_by_token(db_path, token)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid API token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return Principal(username=row["username"], role=row["role"])

    return _authenticate
