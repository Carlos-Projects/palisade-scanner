from scanner.config import Settings
from scanner.domain.models import Finding, ScanReport


class ScoringEngine:
    """Calculates risk score from findings.

    The formula:
      base = 100
      - (critical * weight_critical)
      - (high * weight_high)
      - (medium * weight_medium)
      - (low * weight_low)

    Modifiers:
      + confidence_factor (higher avg confidence = higher score)
      + diversity_bonus (multiple categories = higher concern)

    Score is clamped to 0-100 and mapped to a category.
    """

    def __init__(self, settings: Settings | None = None):
        self.s = settings or Settings()

    def score(self, findings: list[Finding]) -> int:
        if not findings:
            return 0

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_confidence = 0.0
        categories = set()

        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            total_confidence += f.confidence
            if f.category:
                categories.add(f.category)

        base = 100.0
        base -= severity_counts.get("critical", 0) * self.s.risk_weight_critical
        base -= severity_counts.get("high", 0) * self.s.risk_weight_high
        base -= severity_counts.get("medium", 0) * self.s.risk_weight_medium
        base -= severity_counts.get("low", 0) * self.s.risk_weight_low

        n = len(findings)
        avg_confidence = total_confidence / n if n > 0 else 0
        base += avg_confidence * 5

        diversity = len(categories)
        base += min(diversity * 2, 10)

        base = max(0, min(100, int(base)))
        return base

    def category(self, score: int) -> str:
        if score >= self.s.risk_threshold_high:
            return "critical"
        if score >= self.s.risk_threshold_medium:
            return "high"
        if score >= self.s.risk_threshold_low:
            return "medium"
        if score >= self.s.risk_threshold_none:
            return "low"
        return "none"

    def compute(self, findings: list[Finding]) -> tuple[int, str]:
        score = self.score(findings)

        has_real_findings = any(f.severity in ("low", "medium", "high", "critical") for f in findings)
        if not has_real_findings:
            return 0, "none"

        cat = self.category(score)
        return score, cat
