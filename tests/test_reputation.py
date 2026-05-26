
from scanner.domain.models import Finding, ReputationEntry, ScanReport
from scanner.reputation import ReputationEngine, ReputationScorer


def test_scorer_clean():
    scorer = ReputationScorer()
    entry = ReputationEntry(domain="example.com", total_scans=5, total_findings=0,
                             has_https=True)
    score = scorer.score(entry)
    assert score > 90
    assert scorer.trust_level(score, entry) == "trusted"


def test_scorer_malicious():
    scorer = ReputationScorer()
    entry = ReputationEntry(domain="evil.com", total_scans=2, total_findings=8,
                             critical_findings=3, high_findings=3)
    score = scorer.score(entry)
    assert score < 50
    assert scorer.trust_level(score, entry) in ("suspicious", "malicious")


def test_reputation_record_and_query():
    engine = ReputationEngine(db_path=":memory:")
    report = ScanReport(
        url="https://evil.com/test",
        risk_score=80,
        risk_category="high",
        findings=[
            Finding(detector="test", severity="critical", title="Test",
                    snippet="evil", category="jailbreak"),
            Finding(detector="test", severity="high", title="Test2",
                    snippet="exfil", category="exfiltration"),
        ],
        total_findings=2,
    )
    engine.record_scan("https://evil.com/test", report)

    info = engine.query("https://evil.com/test")
    assert info["trust_level"] in ("suspicious", "malicious")
    assert info["total_scans"] >= 1
    assert info["total_findings"] >= 2


def test_reputation_clean():
    engine = ReputationEngine(db_path=":memory:")
    report = ScanReport(url="https://trusted.com", risk_score=0, risk_category="none")
    engine.record_scan("https://trusted.com", report)

    info = engine.query("https://trusted.com")
    assert info["trust_level"] == "unknown"  # not enough scans for trusted


def test_reputation_recent_threats():
    engine = ReputationEngine(db_path=":memory:")
    report = ScanReport(url="https://evil.com", risk_score=90, risk_category="critical",
                         findings=[Finding(detector="t", severity="critical",
                                          title="x", snippet="x", category="jailbreak")],
                         total_findings=1)
    engine.record_scan("https://evil.com", report)

    threats = engine.recent_threats(hours=48)
    assert len(threats) >= 1
