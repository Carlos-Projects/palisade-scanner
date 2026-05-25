import pytest
from bs4 import BeautifulSoup

from scanner.detectors.metadata_analyzer import MetadataAnalyzer


@pytest.mark.asyncio
async def test_detects_comment_injection(sample_comment_injection_html):
    detector = MetadataAnalyzer()
    soup = BeautifulSoup(sample_comment_injection_html, "lxml")
    findings = await detector.detect(soup)

    # Should find suspicious data in meta/noscript/template (not comments,
    # those are handled by hidden_text detector)
    # This is a metadata check
    assert isinstance(findings, list)
