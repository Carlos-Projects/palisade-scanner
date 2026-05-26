import sqlite3
from pathlib import Path
from urllib.parse import urlparse

from scanner.domain.models import ReputationEntry, ScanReport
from scanner.reputation.scorer import ReputationScorer


class ReputationEngine:
    """Web of Trust for URLs based on scan history.

    Assigns trust levels (trusted / suspicious / malicious / unknown)
    and provides a reputation API.
    """

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path or Path.home() / ".pis" / "reputation.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.scorer = ReputationScorer()
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
            CREATE TABLE IF NOT EXISTS reputation (
                domain TEXT NOT NULL,
                path TEXT DEFAULT '',
                trust_level TEXT DEFAULT 'unknown',
                score REAL DEFAULT 0,
                total_scans INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                last_scan_at TEXT,
                last_finding_at TEXT,
                first_seen_at TEXT DEFAULT (datetime('now')),
                critical_findings INTEGER DEFAULT 0,
                high_findings INTEGER DEFAULT 0,
                medium_findings INTEGER DEFAULT 0,
                low_findings INTEGER DEFAULT 0,
                jailbreak_count INTEGER DEFAULT 0,
                exfiltration_count INTEGER DEFAULT 0,
                impersonation_count INTEGER DEFAULT 0,
                hidden_instruction_count INTEGER DEFAULT 0,
                role_override_count INTEGER DEFAULT 0,
                tool_manipulation_count INTEGER DEFAULT 0,
                has_https INTEGER DEFAULT 0,
                PRIMARY KEY (domain, path)
            );

            CREATE TABLE IF NOT EXISTS reputation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                path TEXT DEFAULT '',
                old_trust_level TEXT,
                new_trust_level TEXT,
                old_score REAL,
                new_score REAL,
                reason TEXT,
                changed_at TEXT DEFAULT (datetime('now'))
            );
        """)

    def record_scan(self, url: str, report: ScanReport):
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        path = parsed.path or "/"
        has_https = parsed.scheme == "https"

        cat_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        type_counts = {}
        for f in report.findings:
            cat_counts[f.severity] = cat_counts.get(f.severity, 0) + 1
            if f.category:
                type_counts[f.category] = type_counts.get(f.category, 0) + 1

        c = self.conn
        existing = c.execute(
            "SELECT * FROM reputation WHERE domain = ? AND path = ?", (domain, path)
        ).fetchone()

        if existing:
            c.execute("""
                UPDATE reputation SET
                    total_scans = total_scans + 1,
                    total_findings = total_findings + ?,
                    last_scan_at = datetime('now'),
                    last_finding_at = CASE WHEN ? > 0 THEN datetime('now') ELSE last_finding_at END,
                    critical_findings = critical_findings + ?,
                    high_findings = high_findings + ?,
                    medium_findings = medium_findings + ?,
                    low_findings = low_findings + ?,
                    jailbreak_count = jailbreak_count + ?,
                    exfiltration_count = exfiltration_count + ?,
                    impersonation_count = impersonation_count + ?,
                    hidden_instruction_count = hidden_instruction_count + ?,
                    role_override_count = role_override_count + ?,
                    tool_manipulation_count = tool_manipulation_count + ?,
                    score = ?
                WHERE domain = ? AND path = ?
            """, (
                report.total_findings, report.total_findings,
                cat_counts["critical"], cat_counts["high"],
                cat_counts["medium"], cat_counts["low"],
                type_counts.get("jailbreak", 0), type_counts.get("exfiltration", 0),
                type_counts.get("impersonation", 0), type_counts.get("hidden_instruction", 0),
                type_counts.get("role_override", 0), type_counts.get("tool_manipulation", 0),
                0,  # placeholder, recalculated below
                domain, path,
            ))
        else:
            c.execute("""
                INSERT INTO reputation (domain, path, trust_level, total_scans, total_findings,
                    last_scan_at, last_finding_at, critical_findings, high_findings,
                    medium_findings, low_findings, jailbreak_count, exfiltration_count,
                    impersonation_count, hidden_instruction_count, role_override_count,
                    tool_manipulation_count, has_https)
                VALUES (?, ?, 'unknown', 1, ?, datetime('now'),
                    CASE WHEN ? > 0 THEN datetime('now') ELSE NULL END,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                domain, path, report.total_findings, report.total_findings,
                cat_counts["critical"], cat_counts["high"], cat_counts["medium"],
                cat_counts["low"], type_counts.get("jailbreak", 0),
                type_counts.get("exfiltration", 0), type_counts.get("impersonation", 0),
                type_counts.get("hidden_instruction", 0), type_counts.get("role_override", 0),
                type_counts.get("tool_manipulation", 0), int(has_https),
            ))

        self._recalculate(domain, path)
        self.conn.commit()

    def _recalculate(self, domain: str, path: str):
        row = self.conn.execute(
            "SELECT * FROM reputation WHERE domain = ? AND path = ?", (domain, path)
        ).fetchone()
        if not row:
            return

        entry = ReputationEntry(
            domain=row["domain"],
            path=row["path"],
            total_scans=row["total_scans"],
            total_findings=row["total_findings"],
            critical_findings=row["critical_findings"],
            high_findings=row["high_findings"],
            medium_findings=row["medium_findings"],
            low_findings=row["low_findings"],
            jailbreak_count=row["jailbreak_count"],
            exfiltration_count=row["exfiltration_count"],
            impersonation_count=row["impersonation_count"],
            hidden_instruction_count=row["hidden_instruction_count"],
            role_override_count=row["role_override_count"],
            tool_manipulation_count=row["tool_manipulation_count"],
            has_https=bool(row["has_https"]),
        )

        old_trust = row["trust_level"]
        score = self.scorer.score(entry)
        new_trust = self.scorer.trust_level(score, entry)

        self.conn.execute(
            "UPDATE reputation SET score = ?, trust_level = ? WHERE domain = ? AND path = ?",
            (score, new_trust, domain, path),
        )

        if old_trust != new_trust:
            self.conn.execute("""
                INSERT INTO reputation_history (domain, path, old_trust_level, new_trust_level,
                    old_score, new_score, reason)
                VALUES (?, ?, ?, ?, ?, ?, 'auto')
            """, (domain, path, old_trust, new_trust, row["score"] or 0, score))

    def query(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        path = parsed.path or "/"

        row = self.conn.execute(
            "SELECT * FROM reputation WHERE domain = ? AND path = ?", (domain, path)
        ).fetchone()

        if not row:
            row = self.conn.execute(
                "SELECT * FROM reputation WHERE domain = ? AND path = ''", (domain,)
            ).fetchone()

        if row:
            history = self.conn.execute(
                "SELECT * FROM reputation_history WHERE domain = ? AND path = ? ORDER BY changed_at DESC LIMIT 10",
                (domain, path if row["path"] else row["path"]),
            ).fetchall()
            return {
                "url": url,
                "domain": domain,
                "trust_level": row["trust_level"],
                "score": row["score"],
                "total_scans": row["total_scans"],
                "total_findings": row["total_findings"],
                "last_scan_at": row["last_scan_at"],
                "history": [dict(h) for h in history],
            }

        return {"url": url, "domain": domain, "trust_level": "unknown", "score": 0.0}

    def recent_threats(self, hours: int = 24) -> list[dict]:
        rows = self.conn.execute("""
            SELECT domain, path, trust_level, score, total_scans, total_findings,
                   last_finding_at, critical_findings
            FROM reputation
            WHERE last_finding_at >= datetime('now', ?)
              AND critical_findings > 0
            ORDER BY critical_findings DESC
            LIMIT 50
        """, (f"-{hours} hours",)).fetchall()
        return [dict(r) for r in rows]
