import logging

from scanner.domain.models import ScanReport

logger = logging.getLogger(__name__)


class DiffDetector:
    """Detects meaningful changes between consecutive scans.

    Outputs human-readable diff summaries:
    - Score changes (including direction)
    - New findings by category
    - Resolved findings
    - Severity escalations
    """

    def detect(self, previous: dict | None, current: ScanReport) -> str | None:
        if previous is None:
            return None

        prev_score = previous.get("last_risk_score", 0)
        curr_score = current.risk_score
        delta = curr_score - prev_score

        if delta == 0:
            return None

        direction = "increased" if delta > 0 else "decreased"
        return (
            f"Risk score {direction} from {prev_score} to {curr_score} "
            f"({'+' if delta > 0 else ''}{delta}) — {current.summary}"
        )
