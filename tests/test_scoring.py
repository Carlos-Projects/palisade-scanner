import pytest

from scanner.domain.models import Finding
from scanner.domain.scoring import ScoringEngine


def test_scoring_no_findings():
    engine = ScoringEngine()
    score, cat = engine.compute([])
    assert score == 0
    assert cat == "none"


def test_scoring_single_critical():
    engine = ScoringEngine()
    findings = [
        Finding(
            detector="test",
            severity="critical",
            title="Test critical",
            category="jailbreak",
        )
    ]
    score, cat = engine.compute(findings)
    # 100 - 25 (critical) + 5 (confidence) + 2 (diversity) = 82
    assert score == 82
    assert cat == "critical"


def test_scoring_multiple():
    engine = ScoringEngine()
    findings = [
        Finding(detector="test", severity="critical", title="Critical", category="a"),
        Finding(detector="test", severity="high", title="High", category="b"),
        Finding(detector="test", severity="medium", title="Medium", category="c"),
        Finding(detector="test", severity="low", title="Low", category="d"),
    ]
    score, cat = engine.compute(findings)
    # 100 - 25 - 10 - 3 - 1 + 5 (confidence) + 8 (diversity, capped at 10) = 74
    assert score == 74
    assert cat == "high"


def test_scoring_clean():
    engine = ScoringEngine()
    findings = [
        Finding(detector="test", severity="info", title="Info finding", category="system"),
    ]
    score, cat = engine.compute(findings)
    assert score == 0
    assert cat == "none"


def test_scoring_only_info_and_critical():
    """Mix of info (ignored) and real findings."""
    engine = ScoringEngine()
    findings = [
        Finding(detector="test", severity="info", title="Info", category="system"),
        Finding(detector="test", severity="critical", title="Critical", category="jailbreak"),
    ]
    score, cat = engine.compute(findings)
    # 100 - 25 + 5 (confidence) + 4 (diversity: 2 cats * 2) = 84
    assert score == 84
    assert cat == "critical"
