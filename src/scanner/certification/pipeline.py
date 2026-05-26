import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from scanner.pipeline import PipelineOrchestrator
from scanner.reputation.engine import ReputationEngine


class CertificationPipeline:
    """Full certification flow:

    1. Apply: initial scan + start monitoring period
    2. Monitor: re-scan every 6h for 7 days
    3. Evaluate: check all conditions
    4. Issue: generate certificate with verifiable badge
    5. Maintain: daily re-scans, auto-suspend on risk increase
    """

    MONITOR_PERIOD_DAYS = 7
    MONITOR_SCAN_INTERVAL_HOURS = 6
    CERT_VALIDITY_DAYS = 30
    SUSPEND_THRESHOLD = 30

    def __init__(
        self,
        orchestrator: PipelineOrchestrator,
        reputation: ReputationEngine | None = None,
        db_path: str | Path | None = None,
    ):
        self.orchestrator = orchestrator
        self.reputation = reputation or ReputationEngine()
        self.db_path = Path(db_path or Path.home() / ".pis" / "certificates.db")
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
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                certificate_id TEXT UNIQUE NOT NULL,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                issued_at TEXT,
                expires_at TEXT,
                revoked_at TEXT,
                revoked_reason TEXT,
                initial_scan_json TEXT,
                initial_score REAL,
                total_scans_during_monitoring INTEGER DEFAULT 0,
                avg_score_during_monitoring REAL DEFAULT 0,
                highest_score_during_monitoring REAL DEFAULT 0,
                owner_email TEXT,
                organization TEXT,
                verification_hash TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS monitoring_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                certificate_id TEXT NOT NULL,
                scan_json TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                scanned_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (certificate_id) REFERENCES certificates(certificate_id)
            );
        """)

    async def apply(self, url: str, owner_email: str | None = None,
                    organization: str | None = None) -> dict:
        """Start certification process for a URL."""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        cert_id = self._generate_id(domain)

        initial = await self.orchestrator.scan_url(url)
        if initial.risk_score > 20:
            return {"error": f"URL is not eligible: risk score {initial.risk_score} > 20"}

        self.conn.execute("""
            INSERT INTO certificates (certificate_id, url, domain, owner_email,
                organization, initial_scan_json, initial_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (cert_id, url, domain, owner_email, organization,
              json.dumps(initial.model_dump(mode="json")),
              initial.risk_score))
        self.conn.commit()

        return {
            "certificate_id": cert_id,
            "url": url,
            "status": "monitoring",
            "monitoring_period_days": self.MONITOR_PERIOD_DAYS,
            "initial_risk_score": initial.risk_score,
            "message": "Certification started. Monitoring period: 7 days.",
        }

    async def record_monitoring_scan(self, cert_id: str):
        """Record a monitoring scan. Called by scheduler."""
        cert = self.conn.execute(
            "SELECT * FROM certificates WHERE certificate_id = ?", (cert_id,)
        ).fetchone()
        if not cert or cert["status"] not in ("pending", "monitoring"):
            return

        report = await self.orchestrator.scan_url(cert["url"])
        self.conn.execute("""
            INSERT INTO monitoring_scans (certificate_id, scan_json, risk_score)
            VALUES (?, ?, ?)
        """, (cert_id, json.dumps(report.model_dump(mode="json")),
              report.risk_score))

        self.conn.execute("""
            UPDATE certificates SET
                total_scans_during_monitoring = total_scans_during_monitoring + 1,
                highest_score_during_monitoring = MAX(highest_score_during_monitoring, ?)
            WHERE certificate_id = ?
        """, (report.risk_score, cert_id))

        avg = self.conn.execute(
            "SELECT AVG(risk_score) as avg FROM monitoring_scans WHERE certificate_id = ?",
            (cert_id,),
        ).fetchone()["avg"]
        self.conn.execute(
            "UPDATE certificates SET avg_score_during_monitoring = ? WHERE certificate_id = ?",
            (round(avg or 0, 1), cert_id),
        )
        self.conn.commit()

        if report.risk_score >= self.SUSPEND_THRESHOLD:
            self.revoke(cert_id, f"Risk score {report.risk_score} exceeded threshold during monitoring")

    def evaluate(self, cert_id: str) -> dict | None:
        """Evaluate if a certificate should be issued."""
        cert = self.conn.execute(
            "SELECT * FROM certificates WHERE certificate_id = ?", (cert_id,)
        ).fetchone()
        if not cert or cert["status"] != "pending":
            return None

        total = cert["total_scans_during_monitoring"]
        expected = int(self.MONITOR_PERIOD_DAYS * 24 / self.MONITOR_SCAN_INTERVAL_HOURS)

        if total < expected / 2:
            return {"status": "insufficient_scans", "total": total, "expected": expected}

        if cert["highest_score_during_monitoring"] >= self.SUSPEND_THRESHOLD:
            return {"status": "failed", "reason": "Risk score exceeded threshold during monitoring"}

        self.issue(cert_id)
        return {"status": "certified", "certificate_id": cert_id}

    def issue(self, cert_id: str):
        """Issue a certificate."""
        cert = self.conn.execute(
            "SELECT * FROM certificates WHERE certificate_id = ?", (cert_id,)
        ).fetchone()
        if not cert:
            return

        now = datetime.now(UTC)
        expires = now + timedelta(days=self.CERT_VALIDITY_DAYS)

        raw = f"{cert_id}:{cert['url']}:{now.isoformat()}:{expires.isoformat()}"
        vhash = hashlib.sha256(raw.encode()).hexdigest()[:16]

        self.conn.execute("""
            UPDATE certificates SET
                status = 'active',
                issued_at = ?,
                expires_at = ?,
                verification_hash = ?
            WHERE certificate_id = ?
        """, (now.isoformat(), expires.isoformat(), vhash, cert_id))
        self.conn.commit()

    def revoke(self, cert_id: str, reason: str = ""):
        """Revoke a certificate."""
        self.conn.execute("""
            UPDATE certificates SET status = 'revoked', revoked_at = datetime('now'),
                revoked_reason = ?
            WHERE certificate_id = ?
        """, (reason, cert_id))
        self.conn.commit()

    def verify(self, cert_id: str) -> dict:
        """Verify a certificate's validity."""
        cert = self.conn.execute(
            "SELECT * FROM certificates WHERE certificate_id = ?", (cert_id,)
        ).fetchone()

        if not cert:
            return {"valid": False, "error": "Certificate not found"}

        is_valid = (
            cert["status"] == "active"
            and cert["expires_at"]
            and datetime.fromisoformat(cert["expires_at"]) > datetime.now(UTC)
        )

        return {
            "valid": is_valid,
            "certificate_id": cert["certificate_id"],
            "url": cert["url"],
            "domain": cert["domain"],
            "status": cert["status"],
            "issued_at": cert["issued_at"],
            "expires_at": cert["expires_at"],
            "organization": cert["organization"],
            "verification_hash": cert["verification_hash"],
        }

    def badge_html(self, cert_id: str) -> str | None:
        """Generate embeddable badge HTML."""
        info = self.verify(cert_id)
        if not info["valid"]:
            return None

        return f"""<div style="display:inline-flex;align-items:center;gap:8px;
padding:8px 16px;border:1px solid #2ea043;border-radius:6px;
background:#161b22;font-family:sans-serif;font-size:14px;">
<span style="font-size:20px;">✓</span>
<div>
    <strong style="color:#2ea043;">AgentSafe Verified</strong><br/>
    <small style="color:#8b949e;">{info['url']}<br/>
    Verified · Expires {info['expires_at'][:10]}</small>
</div>
<a href="/certification/verify/{cert_id}"
   style="margin-left:12px;padding:4px 8px;background:#2ea043;
          color:#fff;text-decoration:none;border-radius:4px;font-size:12px;">
   Verify</a>
</div>"""

    def _generate_id(self, domain: str) -> str:
        today = datetime.now(UTC).strftime("%Y%m%d")
        h = hashlib.md5(f"{domain}:{today}".encode()).hexdigest()[:4].upper()
        return f"AS-{today}-{h}"
