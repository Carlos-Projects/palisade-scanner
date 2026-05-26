import json
import sqlite3
from pathlib import Path

from scanner.domain.models import ScanReport


class MonitorStore:
    """SQLite-backed store for scan history, URL tracking, and alerts."""

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path or Path.home() / ".pis" / "monitor.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self):
        c = self.conn
        c.executescript("""
            CREATE TABLE IF NOT EXISTS monitored_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                label TEXT,
                interval_hours REAL NOT NULL DEFAULT 6,
                last_scan_at TEXT,
                last_risk_score INTEGER DEFAULT 0,
                last_risk_category TEXT DEFAULT 'none',
                highest_risk_score INTEGER DEFAULT 0,
                total_scans INTEGER DEFAULT 0,
                alert_on_change BOOLEAN DEFAULT 1,
                alert_webhook TEXT,
                alert_slack TEXT,
                alert_email TEXT,
                enabled BOOLEAN DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now')),
                tags TEXT DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_id INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_category TEXT NOT NULL,
                total_findings INTEGER DEFAULT 0,
                findings_json TEXT DEFAULT '[]',
                scan_time_ms INTEGER DEFAULT 0,
                scanned_at TEXT DEFAULT (datetime('now')),
                diff_summary TEXT,
                FOREIGN KEY (url_id) REFERENCES monitored_urls(id)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_id INTEGER NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                delivered BOOLEAN DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                delivered_at TEXT,
                FOREIGN KEY (url_id) REFERENCES monitored_urls(id)
            );

            CREATE INDEX IF NOT EXISTS idx_scan_history_url ON scan_history(url_id, scanned_at DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_pending ON alerts(delivered, created_at);
        """)

    def add_url(
        self, url: str, interval_hours: float = 6, label: str = "", webhook: str = "", tags: list[str] | None = None
    ) -> int:
        c = self.conn
        c.execute(
            "INSERT OR IGNORE INTO monitored_urls (url, label, interval_hours, alert_webhook, tags) VALUES (?, ?, ?, ?, ?)",
            (url, label, interval_hours, webhook, json.dumps(tags or [])),
        )
        self.conn.commit()
        row = c.execute("SELECT id FROM monitored_urls WHERE url = ?", (url,)).fetchone()
        return row["id"] if row else -1

    def remove_url(self, url: str):
        self.conn.execute("DELETE FROM monitored_urls WHERE url = ?", (url,))
        self.conn.commit()

    def get_urls(self, enabled_only: bool = True) -> list[dict]:
        q = "SELECT * FROM monitored_urls"
        if enabled_only:
            q += " WHERE enabled = 1"
        rows = self.conn.execute(q).fetchall()
        return [dict(r) for r in rows]

    def get_url(self, url_id: int) -> dict | None:
        row = self.conn.execute("SELECT * FROM monitored_urls WHERE id = ?", (url_id,)).fetchone()
        return dict(row) if row else None

    def record_scan(self, url_id: int, report: ScanReport) -> int:
        diff = ""
        prev = self.conn.execute(
            "SELECT risk_score, findings_json FROM scan_history WHERE url_id = ? ORDER BY scanned_at DESC LIMIT 1",
            (url_id,),
        ).fetchone()

        if prev:
            prev_score = prev["risk_score"]
            delta = report.risk_score - prev_score
            if delta != 0:
                diff = f"Score changed from {prev_score} to {report.risk_score} ({'+' if delta > 0 else ''}{delta})"

        cursor = self.conn.cursor()
        cursor.execute(
            """INSERT INTO scan_history (url_id, risk_score, risk_category, total_findings,
               findings_json, scan_time_ms, diff_summary) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                url_id,
                report.risk_score,
                report.risk_category,
                report.total_findings,
                json.dumps([f.model_dump(mode="json") for f in report.findings]),
                report.scan_time_ms,
                diff,
            ),
        )

        cursor.execute(
            """UPDATE monitored_urls SET last_scan_at = datetime('now'),
               last_risk_score = ?, last_risk_category = ?,
               total_scans = total_scans + 1,
               highest_risk_score = MAX(highest_risk_score, ?)
               WHERE id = ?""",
            (report.risk_score, report.risk_category, report.risk_score, url_id),
        )
        self.conn.commit()
        return cursor.lastrowid or 0

    def get_history(self, url_id: int, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM scan_history WHERE url_id = ? ORDER BY scanned_at DESC LIMIT ?",
            (url_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_recent_scans(self, hours: int = 24) -> list[dict]:
        rows = self.conn.execute(
            """SELECT u.url, u.label, h.risk_score, h.risk_category, h.total_findings, h.scanned_at
               FROM scan_history h JOIN monitored_urls u ON h.url_id = u.id
               WHERE h.scanned_at >= datetime('now', ?)
               ORDER BY h.scanned_at DESC""",
            (f"-{hours} hours",),
        ).fetchall()
        return [dict(r) for r in rows]

    def create_alert(self, url_id: int, alert_type: str, severity: str, message: str) -> int:
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (url_id, alert_type, severity, message) VALUES (?, ?, ?, ?)",
            (url_id, alert_type, severity, message),
        )
        self.conn.commit()
        return cursor.lastrowid or 0

    def get_pending_alerts(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT a.*, u.url, u.alert_webhook, u.alert_slack FROM alerts a "
            "JOIN monitored_urls u ON a.url_id = u.id WHERE a.delivered = 0 ORDER BY a.created_at"
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_alert_delivered(self, alert_id: int):
        self.conn.execute(
            "UPDATE alerts SET delivered = 1, delivered_at = datetime('now') WHERE id = ?",
            (alert_id,),
        )
        self.conn.commit()

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None
