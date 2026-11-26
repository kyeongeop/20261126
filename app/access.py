from __future__ import annotations

from collections.abc import Iterator
from sqlite3 import Connection, Row
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Query, Request, status

from app.db import Database


def get_db(request: Request) -> Iterator[Connection]:
    database: Database = request.app.state.database
    connection = database.connect()
    try:
        yield connection
    finally:
        connection.close()


def get_actor_id(
    x_analyst_id: Annotated[int | None, Header(alias="X-Analyst-Id")] = None,
    analyst_id: Annotated[int | None, Query()] = None,
) -> int:
    actor_id = x_analyst_id or analyst_id
    if actor_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="请通过 X-Analyst-Id 请求头或 actor_id 查询参数提供分析员身份",
        )
    if actor_id < 1:
        raise HTTPException(status_code=401, detail="分析员标识无效")
    return actor_id


DbConnection = Annotated[Connection, Depends(get_db)]
ActorId = Annotated[int, Depends(get_actor_id)]


def require_analyst(connection: Connection, analyst_id: int) -> Row:
    row = connection.execute(
        "SELECT id, name, created_at FROM analysts WHERE id = ?", (analyst_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="分析员不存在"
        )
    return row


def require_case_access(
    connection: Connection,
    case_id: int,
    analyst_id: int,
    *,
    write: bool = False,
) -> tuple[Row, str]:
    require_analyst(connection, analyst_id)
    case_row = connection.execute(
        """
        SELECT c.*, a.name AS owner_name
        FROM cases c
        JOIN analysts a ON a.id = c.owner_id
        WHERE c.id = ?
        """,
        (case_id,),
    ).fetchone()
    if case_row is None:
        raise HTTPException(status_code=404, detail="案件不存在")

    member = connection.execute(
        "SELECT access_level FROM case_members WHERE case_id = ? AND analyst_id = ?",
        (case_id, analyst_id),
    ).fetchone()
    if member is None:
        raise HTTPException(status_code=403, detail="当前分析员无权访问该案件")

    access_level = member["access_level"]
    if write and access_level != "owner":
        raise HTTPException(
            status_code=403,
            detail="当前分析员对该案件只有只读权限",
        )
    return case_row, access_level


def case_dict(case_row: Row, access_level: str) -> dict[str, object]:
    return {
        "id": case_row["id"],
        "title": case_row["title"],
        "description": case_row["description"],
        "status": case_row["status"],
        "owner_id": case_row["owner_id"],
        "owner_name": case_row["owner_name"],
        "access_level": access_level,
        "created_at": case_row["created_at"],
        "updated_at": case_row["updated_at"],
    }
