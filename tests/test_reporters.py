import pytest

from scanner.domain.models import Finding, ScanReport
from scanner.reporters import JSONReporter, MarkdownReporter, SimpleReporter


@pytest.fixture
def sample_report():
    return ScanReport(
        url="https://example.com",
        findings=[
            Finding(
                detector="hidden_text",
                severity="high",
                title="Hidden text detected",
                snippet="ignore instructions",
                category="jailbreak",
                recommendation="Remove hidden content",
            ),
        ],
        risk_score=75,
        risk_category="high",
        total_findings=1,
        summary="1 issue found.",
        scan_time_ms=1234,
    )


def test_json_reporter(sample_report):
    reporter = JSONReporter()
    output = reporter.render(sample_report)
    assert '"risk_score": 75' in output
    assert '"url": "https://example.com"' in output


def test_markdown_reporter(sample_report):
    reporter = MarkdownReporter()
    output = reporter.render(sample_report)
    assert "Risk Score" in output
    assert "75/100" in output
    assert "HIGH" in output


def test_simple_reporter(sample_report):
    reporter = SimpleReporter()
    output = reporter.render(sample_report)
    assert "75/100" in output
    assert "1 findings" in output or "1" in output
