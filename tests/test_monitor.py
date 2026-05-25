import json
import tempfile
from pathlib import Path

import pytest

from scanner.monitor import MonitorStore, Alerter
from scanner.domain.models import Finding, ScanReport


@pytest.fixture
def monitor_store():
    db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    store = MonitorStore(db_path=db.name)
    yield store
    store.close()
    Path(db.name).unlink(missing_ok=True)


def test_monitor_add_and_list_urls(monitor_store):
    uid = monitor_store.add_url("https://example.com", interval_hours=6, label="test")
    assert uid > 0

    urls = monitor_store.get_urls()
    assert len(urls) == 1
    assert urls[0]["url"] == "https://example.com"
    assert urls[0]["interval_hours"] == 6.0


def test_monitor_dedup(monitor_store):
    monitor_store.add_url("https://example.com")
    monitor_store.add_url("https://example.com")  # same URL
    urls = monitor_store.get_urls()
    assert len(urls) == 1


def test_monitor_remove_url(monitor_store):
    monitor_store.add_url("https://example.com")
    monitor_store.remove_url("https://example.com")
    assert len(monitor_store.get_urls()) == 0


def test_monitor_record_and_history(monitor_store):
    uid = monitor_store.add_url("https://example.com")
    report = ScanReport(
        url="https://example.com",
        risk_score=50,
        risk_category="high",
        total_findings=3,
        scan_time_ms=100,
    )
    sid = monitor_store.record_scan(uid, report)
    assert sid > 0

    history = monitor_store.get_history(uid)
    assert len(history) == 1
    assert history[0]["risk_score"] == 50


def test_monitor_alert(monitor_store):
    uid = monitor_store.add_url("https://example.com")
    aid = monitor_store.create_alert(uid, "test_alert", "high", "Test alert message")
    assert aid > 0

    pending = monitor_store.get_pending_alerts()
    assert len(pending) == 1
    assert pending[0]["alert_type"] == "test_alert"
    assert pending[0]["delivered"] == 0


def test_monitor_mark_alert_delivered(monitor_store):
    uid = monitor_store.add_url("https://example.com")
    aid = monitor_store.create_alert(uid, "test", "low", "msg")
    monitor_store.mark_alert_delivered(aid)

    pending = monitor_store.get_pending_alerts()
    assert len(pending) == 0
