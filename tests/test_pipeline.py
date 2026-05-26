import pytest

from scanner.config import Settings
from scanner.pipeline import PipelineOrchestrator


@pytest.mark.asyncio
async def test_pipeline_full_scan(sample_adversarial_html):
    """Test that the full pipeline produces a report."""
    settings = Settings()
    orchestrator = PipelineOrchestrator(settings=settings)

    report = await orchestrator.scan_content(sample_adversarial_html, url="test://adversarial")

    assert report is not None
    assert report.total_findings >= 1
    assert report.risk_score > 0
    assert report.risk_category in ("none", "low", "medium", "high", "critical")
    assert len(report.findings) >= 1
    assert report.scan_time_ms >= 0


@pytest.mark.asyncio
async def test_pipeline_clean_scan(sample_clean_html):
    """Test that clean content produces few/no findings."""
    settings = Settings()
    orchestrator = PipelineOrchestrator(settings=settings)

    report = await orchestrator.scan_content(sample_clean_html, url="test://clean")

    assert report is not None
    critical_high = [f for f in report.findings if f.severity in ("critical", "high")]
    assert len(critical_high) == 0, f"Clean page should have no critical/high findings: {len(critical_high)}"


@pytest.mark.asyncio
async def test_pipeline_report_structure():
    """Verify report structure contains all expected fields."""
    from scanner.config import Settings
    from scanner.pipeline import PipelineOrchestrator

    settings = Settings()
    orchestrator = PipelineOrchestrator(settings=settings)

    html = "<html><body><p>Test content</p></body></html>"
    report = await orchestrator.scan_content(html, url="test://structure")

    assert hasattr(report, "url")
    assert hasattr(report, "risk_score")
    assert hasattr(report, "risk_category")
    assert hasattr(report, "findings")
    assert hasattr(report, "summary")
    assert hasattr(report, "scan_time_ms")
    assert hasattr(report, "timestamp")
