import pytest
from bs4 import BeautifulSoup

from scanner.detectors.stego_markers import StegoMarkersDetector


@pytest.mark.asyncio
async def test_detects_st3gg_marker():
    detector = StegoMarkersDetector()
    with open("tests/fixtures/stego_markers.html") as f:
        soup = BeautifulSoup(f.read(), "lxml")
    findings = await detector.detect(soup)
    st3gg = [f for f in findings if f.category == "stego_marker"]
    assert len(st3gg) >= 1
    assert any("ST3GG" in f.snippet for f in st3gg)


@pytest.mark.asyncio
async def test_detects_parseltongue_marker():
    detector = StegoMarkersDetector()
    with open("tests/fixtures/stego_markers.html") as f:
        soup = BeautifulSoup(f.read(), "lxml")
    findings = await detector.detect(soup)
    pt = [f for f in findings if "parseltongue" in f.description.lower()]
    assert len(pt) >= 1


@pytest.mark.asyncio
async def test_clean_page_no_false_positives(sample_clean_html):
    detector = StegoMarkersDetector()
    soup = BeautifulSoup(sample_clean_html, "lxml")
    findings = await detector.detect(soup)
    assert len(findings) == 0
