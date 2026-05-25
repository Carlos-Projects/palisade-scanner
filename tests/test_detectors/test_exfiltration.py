import pytest
from bs4 import BeautifulSoup

from scanner.detectors.exfiltration import ExfiltrationDetector


@pytest.mark.asyncio
async def test_detects_exfiltration_urls(sample_exfiltration_html):
    detector = ExfiltrationDetector()
    soup = BeautifulSoup(sample_exfiltration_html, "lxml")
    findings = await detector.detect(soup)

    assert len(findings) >= 1, "Should detect exfiltration patterns"
    assert any("webhook" in f.snippet.lower() for f in findings)
