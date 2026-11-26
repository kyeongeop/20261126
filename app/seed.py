"""写入演示用事故时间线数据。数据相对当前时间生成，保证 LAST 窗口可直接体验。"""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone


def iso_utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def insert_event(
    conn: sqlite3.Connection,
    *,
    epoch: float,
    host: str,
    service: str,
    level: str,
    message: str,
    tags: list[str] | tuple[str, ...] = (),
    evidence: list[tuple[str, str, str | None]] | tuple = (),
) -> int:
    cur = conn.execute(
        "INSERT INTO events (epoch, ts, host, service, level, message) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (epoch, iso_utc(epoch), host, service, level.lower(), message),
    )
    event_id = int(cur.lastrowid)
    for tag in tags:
        conn.execute(
            "INSERT OR IGNORE INTO event_tags (event_id, tag) VALUES (?, ?)",
            (event_id, tag.lower()),
        )
    for kind, label, ref in evidence:
        conn.execute(
            "INSERT INTO evidence (event_id, kind, label, ref) VALUES (?, ?, ?, ?)",
            (event_id, kind, label, ref),
        )
    return event_id


# (多少分钟前, host, service, level, message, [tags], [(kind,label,ref)])
DEMO_ROWS: list[tuple] = [
    (195, "web-01", "nginx", "info", "nginx worker 进程启动", [], []),
    (180, "api-01", "checkout", "info", "checkout v2.2.9 运行稳定", [], []),
    (170, "web-02", "nginx", "warn", "数据盘使用率达到 72%", ["disk"],
     [("metric", "node_disk_usage", "https://metrics.internal/d/node")]),
    (160, "db-01", "postgres", "info", "慢查询巡检完成，无异常", ["metrics"], []),
    (126, "ops-01", "deploy", "info", "发布流水线 #482 开始：checkout v2.3.0",
     ["deploy"], [("link", "pipeline-482", "https://ci.internal/pipelines/482")]),
    (123, "api-01", "checkout", "info", "v2.3.0 镜像拉取完成", ["deploy"], []),
    (120, "api-01", "checkout", "info", "滚动更新批次 1/3 就绪", ["deploy"], []),
    (117, "api-02", "checkout", "info", "滚动更新批次 2/3 就绪", ["deploy"], []),
    (112, "api-01", "checkout", "info", "特性开关 new_pay_route 全量打开",
     ["config-change", "deploy"],
     [("note", "支付路由切换到新渠道分组", None)]),
    (118, "db-01", "postgres", "warn", "慢查询数量环比上升 3 倍",
     ["db-lock", "metrics"],
     [("metric", "pg_slow_queries", "https://metrics.internal/d/pg")]),
    (106, "api-01", "checkout", "warn", "支付渠道 P99 延迟升至 1.8s",
     ["latency", "metrics"], []),
    (105, "cache-01", "cache", "warn", "热点 key 连接数激增，命中率下滑",
     ["latency"], []),
    (98, "db-01", "postgres", "warn", "检测到行锁等待：orders / payments",
     ["db-lock"],
     [("trace", "lock-wait-trace-7741", "trace://7741")]),
    (92, "api-01", "checkout", "error",
     "支付请求超时：gateway read timeout after 3000ms",
     ["timeout", "trace"],
     [("log", "checkout-timeout-stack", "log://api-01/checkout/9f31"),
      ("trace", "trace-abc-001", "trace://abc001")]),
    (91, "api-02", "checkout", "error",
     "支付请求超时：gateway read timeout after 3000ms",
     ["timeout"], []),
    (89, "api-03", "checkout", "error",
     "HikariPool 连接耗尽，获取连接等待 30000ms",
     ["db-lock", "timeout"],
     [("log", "hikari-pool-exhausted", "log://api-03/pool")]),
    (85, "web-01", "nginx", "error",
     "upstream timed out (110: Connection timed out)",
     ["timeout"], []),
    (82, "web-01", "nginx", "error", "502 Bad Gateway: POST /api/checkout",
     ["timeout", "customer-report"],
     [("note", "多名用户反馈结账页转圈后报 502", None)]),
    (80, "web-02", "nginx", "error", "504 Gateway Timeout: POST /api/pay",
     ["timeout", "customer-report"],
     [("screenshot", "customer-checkout-504.png", None)]),
    (78, "api-01", "checkout", "error", "错误率突破 SLO：5 分钟错误率 12.4%",
     ["slo-burn", "metrics"],
     [("metric", "checkout-error-rate", "https://metrics.internal/d/slo")]),
    (75, "ops-01", "alert", "critical",
     "P1 告警触发：checkout 错误率 > 5% 持续 3 分钟",
     ["alert", "slo-burn"], []),
    (70, "api-01", "checkout", "warn", "检测到重试风暴：retry QPS 达基线 8 倍",
     ["retry-storm", "trace"], []),
    (64, "db-01", "postgres", "error",
     "deadlock detected，事务 28841 被回滚",
     ["db-lock"],
     [("log", "postgres-deadlock-log", "log://db-01/deadlock-28841")]),
    (58, "api-02", "checkout", "error",
     "NullPointerException at PayRouteSelector.select(PayRouteSelector.java:87)",
     ["bug", "stacktrace"],
     [("log", "npe-stacktrace", "log://api-02/npe")]),
    (52, "ops-01", "deploy", "warn", "暂停滚动发布，批次 3/3 停止推进",
     ["deploy", "mitigate"], []),
    (47, "ops-01", "config", "warn", "关闭特性开关 new_pay_route",
     ["config-change", "mitigate"], []),
    (40, "api-01", "checkout", "warn", "错误率短暂回落至 6%，仍高于 SLO",
     ["mitigate", "metrics"], []),
    (33, "ops-01", "deploy", "info", "执行回滚：checkout v2.3.0 -> v2.2.9",
     ["rollback", "deploy", "mitigate"],
     [("link", "rollback-runbook", "https://wiki.internal/rca/rollback")]),
    (28, "api-01", "checkout", "info", "回滚完成，就绪探针全部通过",
     ["rollback", "verified"], []),
    (24, "db-01", "postgres", "info", "行锁等待队列清空",
     ["recovery", "db-lock"], []),
    (20, "cache-01", "cache", "info", "缓存命中率恢复至 97.2%",
     ["recovery", "metrics"], []),
    (15, "api-01", "checkout", "info", "错误率恢复基线 0.3%",
     ["recovery", "verified", "metrics"], []),
    (12, "web-01", "nginx", "info", "5xx 计数归零",
     ["recovery", "verified"], []),
    (9, "ops-01", "support", "info", "客服确认新增客诉停止",
     ["customer-report", "verified"], []),
    (6, "ops-01", "rca", "info",
     "RCA 草稿：新支付路由放大行锁等待，叠加重试导致超时雪崩",
     ["rca"],
     [("link", "RCA-2026-1126", "https://wiki.internal/rca/RCA-2026-1126")]),
    (3, "ops-01", "rca", "info", "证据链复核完成并关联到时间线",
     ["rca", "evidence-reviewed"],
     [("note", "共关联 6 条日志、3 条 trace、4 个指标面板", None)]),
]


def seed_demo(conn: sqlite3.Connection, *, now: float | None = None) -> int:
    """写入演示数据；调用方需先 init_db。返回写入事件数。"""
    now = time.time() if now is None else now
    for minutes_ago, host, service, level, message, tags, evidence in DEMO_ROWS:
        insert_event(
            conn,
            epoch=now - minutes_ago * 60,
            host=host,
            service=service,
            level=level,
            message=message,
            tags=tags,
            evidence=evidence,
        )
    conn.commit()
    return len(DEMO_ROWS)
