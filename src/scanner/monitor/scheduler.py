import logging
from datetime import UTC, datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from scanner.monitor.alerter import Alerter
from scanner.monitor.diff import DiffDetector
from scanner.monitor.store import MonitorStore
from scanner.pipeline import PipelineOrchestrator

logger = logging.getLogger(__name__)


class MonitorScheduler:
    """Schedules periodic re-scans of monitored URLs.

    Uses APScheduler to run scans at configurable intervals.
    Detects score changes and triggers alerts.
    """

    def __init__(
        self,
        store: MonitorStore,
        orchestrator: PipelineOrchestrator,
        alerter: Alerter | None = None,
    ):
        self.store = store
        self.orchestrator = orchestrator
        self.alerter = alerter or Alerter(store)
        self.diff = DiffDetector()
        self.scheduler = AsyncIOScheduler()
        self._tasks: dict[int, str] = {}

    def start(self):
        self.scheduler.start()
        self._schedule_all()

    def stop(self):
        self.scheduler.shutdown(wait=False)

    def _schedule_all(self):
        urls = self.store.get_urls(enabled_only=True)
        for entry in urls:
            self._schedule_one(entry)

    def _schedule_one(self, entry: dict):
        job_id = f"monitor-{entry['id']}"
        interval = max(entry["interval_hours"] or 6, 0.5)  # min 30 min

        self.scheduler.add_job(
            self._run_scan,
            trigger="interval",
            hours=interval,
            id=job_id,
            args=[entry],
            replace_existing=True,
            next_run_time=datetime.now(UTC),  # run immediately
        )
        self._tasks[entry["id"]] = job_id
        logger.info(f"Scheduled monitor for {entry['url']} every {interval}h")

    async def add_url(self, url: str, interval_hours: float = 6,
                      label: str = "", webhook: str = "", tags: list[str] | None = None):
        url_id = self.store.add_url(url, interval_hours, label, webhook, tags)
        if url_id > 0:
            entry = self.store.get_url(url_id)
            if entry:
                self._schedule_one(entry)
        return url_id

    async def remove_url(self, url: str):
        entries = [e for e in self.store.get_urls(enabled_only=False) if e["url"] == url]
        for e in entries:
            job_id = self._tasks.pop(e["id"], None)
            if job_id:
                self.scheduler.remove_job(job_id)
        self.store.remove_url(url)

    async def _run_scan(self, entry: dict):
        url = entry["url"]
        logger.info(f"Monitor scan: {url}")

        try:
            report = await self.orchestrator.scan_url(url)
            scan_id = self.store.record_scan(entry["id"], report)

            score_change = self.diff.detect(entry, report)
            if score_change:
                alert = self.store.create_alert(
                    url_id=entry["id"],
                    alert_type="score_change",
                    severity=report.risk_category,
                    message=score_change,
                )
                await self.alerter.dispatch(alert)

            if report.risk_score >= 40:
                alert = self.store.create_alert(
                    url_id=entry["id"],
                    alert_type="high_risk",
                    severity=report.risk_category,
                    message=f"Risk score {report.risk_score}/100 ({report.risk_category}): {report.summary}",
                )
                await self.alerter.dispatch(alert)

        except Exception as e:
            logger.error(f"Monitor scan failed for {url}: {e}")
            self.store.create_alert(
                url_id=entry["id"],
                alert_type="scan_error",
                severity="medium",
                message=f"Scan failed: {e}",
            )
