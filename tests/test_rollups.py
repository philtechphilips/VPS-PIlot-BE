"""Hourly metric rollups for long charts."""

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.servers import service
from app.servers.models import MetricRollup, MetricSample
from tests.test_servers import enrolled_agent


def _sample(server_id: str, ts: datetime, cpu: float) -> MetricSample:
    return MetricSample(
        server_id=server_id, ts=ts, cpu_percent=cpu, memory_percent=50, memory_used=1,
        swap_percent=0, disk_percent=40, disk_used=1, inode_percent=None, load_1=1,
        load_5=1, load_15=1, net_rx_bps=100, net_tx_bps=50,
    )  # fmt: skip


def test_hours_roll_up_once_and_skip_gaps(client, admin_headers, db: Session):
    server_id, _ = enrolled_agent(client, admin_headers)
    hour = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    old = hour - timedelta(days=12)
    db.add_all(
        [
            # Twelve days ago (before a long gap), then the last two hours.
            _sample(server_id, old + timedelta(minutes=5), 10),
            _sample(server_id, hour - timedelta(hours=2, minutes=-1), 20),
            _sample(server_id, hour - timedelta(hours=2, minutes=-30), 40),
            _sample(server_id, hour - timedelta(minutes=50), 90),
            # The current hour isn't finished: not rolled up yet.
            _sample(server_id, hour + timedelta(minutes=1), 99),
        ]
    )
    db.commit()
    # Catch-up is bounded per call; keep going until nothing is left.
    total = 0
    while written := service.rollup_due(db):
        total += written
    assert total == 3
    rows = db.query(MetricRollup).order_by(MetricRollup.hour).all()
    assert [_naive(r.hour) for r in rows] == [
        _naive(old),
        _naive(hour - timedelta(hours=2)),
        _naive(hour - timedelta(hours=1)),
    ]
    assert (rows[1].cpu_percent, rows[1].cpu_max, rows[1].samples) == (30.0, 40.0, 2)
    assert service.rollup_due(db) == 0  # idempotent

    # 30 days in 60 points: 12-hour buckets, so the last two hours merge.
    series = service.metric_series(db, server_id, "30d")
    assert len(series) == 2 and series[-1]["cpu_percent"] == 60.0
    response = client.get(
        f"/api/v1/servers/{server_id}/metrics?range=90d", headers=admin_headers
    )
    assert response.status_code == 200 and len(response.json()) == 2


def _naive(value: datetime) -> datetime:
    return value.replace(tzinfo=None)
