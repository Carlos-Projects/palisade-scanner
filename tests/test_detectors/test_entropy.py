import pytest
from bs4 import BeautifulSoup

from scanner.detectors.entropy import EntropyAnalyzer


@pytest.mark.asyncio
async def test_detects_base64_encoded():
    detector = EntropyAnalyzer()
    with open("tests/fixtures/encoded_content.html") as f:
        soup = BeautifulSoup(f.read(), "lxml")
    findings = await detector.detect(soup)
    b64 = [f for f in findings if "Base64" in f.title or "base64" in f.description.lower()]
    assert len(b64) >= 1


@pytest.mark.asyncio
async def test_detects_hex_encoded():
    detector = EntropyAnalyzer()
    with open("tests/fixtures/encoded_content.html") as f:
        soup = BeautifulSoup(f.read(), "lxml")
    findings = await detector.detect(soup)
    hex_findings = [f for f in findings if "Hex" in f.title or "hex" in f.description.lower()]
    assert len(hex_findings) >= 1


@pytest.mark.asyncio
async def test_clean_page_no_false_positives(sample_clean_html):
    detector = EntropyAnalyzer()
    soup = BeautifulSoup(sample_clean_html, "lxml")
    findings = await detector.detect(soup)
    assert len(findings) == 0
