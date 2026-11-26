"""pytest 公共夹具：固定时间的小型事故数据集 + TestClient。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.db import connect, init_db
from app.main import create_app
from app.seed import insert_event

BASE_EPOCH = 1_764_200_000.0  # 固定基准时间，保证测试确定
# 查询时钟：基准后 70 分钟
NOW = BASE_EPOCH + 70 * 60


# (分钟偏移, host, service, level, message, tags)
SAMPLE_ROWS = [
    (-30, "db-01", "postgres", "error", "disk volume usage 85% on /data", ["disk"]),
    (0, "ops-01", "deploy", "info", "release pipeline 482 started", ["deploy"]),
    (2, "api-01", "checkout", "info",
     "feature flag new_pay_route enabled", ["deploy", "config-change"]),
    (9, "db-01", "postgres", "warn", "slow query count increased",
     ["db-lock", "metrics"]),
    (12, "api-01", "checkout", "error",
     "payment gateway read timeout after 3000ms", ["timeout", "trace"]),
    (13, "api-02", "checkout", "error",
     "payment gateway read timeout after 3000ms", ["timeout"]),
    (15, "db-01", "postgres", "error",
     "connection pool exhausted while waiting for row lock",
     ["db-lock", "timeout"]),
    (22, "web-01", "nginx", "error",
     "upstream timed out and 502 returned", ["timeout", "customer-report"]),
    (40, "api-01", "checkout", "warn", "retry storm detected", ["trace"]),
    (60, "ops-01", "deploy", "info",
     "rollback checkout v2.3.0 to v2.2.9", ["rollback", "deploy"]),
    (66, "api-01", "checkout", "info",
     "error rate back to baseline", ["recovery", "metrics"]),
    (70, "api-01", "checkout", "info",
     "health check ok", ["verified"]),
]


def seed_sample(conn, base: float = BASE_EPOCH) -> None:
    for minute, host, service, level, message, tags in SAMPLE_ROWS:
        insert_event(
            conn,
            epoch=base + minute * 60,
            host=host,
            service=service,
            level=level,
            message=message,
            tags=tags,
            evidence=[("log", f"log-for-{minute}", "log://x")] if level == "error" else [],
        )
    conn.commit()


@pytest.fixture
def conn():
    c = connect(":memory:")
    init_db(c)
    seed_sample(c)
    yield c
    c.close()


@pytest.fixture
def repo(conn):
    from app.repository import TimelineRepository

    return TimelineRepository(conn)


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "timeline-test.db"
    c = connect(path)
    init_db(c)
    seed_sample(c)
    c.close()
    return path


@pytest.fixture
def client(db_path):
    app = create_app(db_path, seed=False)
    with TestClient(app) as test_client:
        yield test_client
