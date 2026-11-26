"""TQL 命令行入口：python -m app.cli 'level = "error" AFTER #deploy WITHIN 20m'。"""

from __future__ import annotations

import argparse
import sys

from . import config
from .db import connect, init_db, is_empty
from .exporting import to_csv, to_json
from .repository import TimelineRepository
from .seed import seed_demo
from .tql import TQLError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tql", description="事故时间线 TQL 本地查询")
    p.add_argument("query", nargs="?", default="", help="TQL 查询串；留空返回全部")
    p.add_argument("--db", default=str(config.DB_PATH), help="SQLite 数据库路径")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--order", choices=["asc", "desc"], default="asc")
    p.add_argument("--now", type=float, default=None, help="查询时钟（epoch 秒），便于复现")
    p.add_argument("--csv", action="store_true", help="以 CSV 输出")
    p.add_argument("--json", action="store_true", help="以 JSON 输出")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    conn = connect(args.db)
    init_db(conn)
    if is_empty(conn):
        seed_demo(conn)
    repo = TimelineRepository(conn)
    try:
        result = repo.search_tql(
            args.query, now=args.now, limit=args.limit, order=args.order
        )
    except TQLError as exc:
        print(exc.render(), file=sys.stderr)
        return 2

    if args.csv:
        sys.stdout.write("﻿" + to_csv(result["items"]))
        return 0
    if args.json:
        print(to_json(result["items"]))
        return 0

    for ev in result["items"]:
        tags = (" #" + " #".join(ev["tags"])) if ev["tags"] else ""
        print(f"{ev['ts']}  {ev['host']:<8} {ev['level']:<8} {ev['message']}{tags}")
    tail = f"\n匹配 {result['total']} 条，显示 {result['returned']} 条"
    if result["truncated"]:
        tail += "（已达 limit，更多结果请调大 --limit 或导出）"
    print(tail)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
