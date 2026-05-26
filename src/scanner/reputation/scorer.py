from datetime import UTC, datetime

from scanner.domain.models import ReputationEntry


class ReputationScorer:
    """Calculates reputation score and trust level.

    Formula:
      base = 100
      - critical * 25
      - high * 10
      - medium * 3
      - low * 1

    Modifiers (capped):
      + total_scans * 0.5  (confidence, max +15)
      + days_clean * 0.1   (recovery, max +20)
      + has_https ? 5 : 0
    """

    def score(self, entry: ReputationEntry) -> float:
        base = 100.0

        base -= entry.critical_findings * 25
        base -= entry.high_findings * 10
        base -= entry.medium_findings * 3
        base -= entry.low_findings * 1

        base += min(entry.total_scans * 0.5, 15)

        if entry.last_finding_at:
            days_clean = (datetime.now(UTC) - entry.last_finding_at).days
            base += min(days_clean * 0.1, 20)

        if entry.has_https:
            base += 5

        return max(0, min(100, base))

    def trust_level(self, score: float, entry: ReputationEntry) -> str:
        if entry.total_findings == 0:
            if entry.total_scans >= 3:
                return "trusted"
            return "unknown"
        if score >= 80 and entry.total_scans >= 3:
            return "trusted"
        if score >= 50:
            return "suspicious"
        return "malicious"
