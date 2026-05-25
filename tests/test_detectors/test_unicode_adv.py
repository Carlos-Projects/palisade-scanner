import pytest
from bs4 import BeautifulSoup

from scanner.detectors.unicode_adv import AdvancedUnicodeDetector


@pytest.mark.asyncio
async def test_detects_bidi_overrides(sample_comment_injection_html):
    # sample has comment injections but no bidi
    detector = AdvancedUnicodeDetector()
    soup = BeautifulSoup(sample_comment_injection_html, "lxml")
    findings = await detector.detect(soup)
    bidi = [f for f in findings if "Bidi" in f.title]
    # No bidi in this fixture
    assert len(bidi) == 0


@pytest.mark.asyncio
async def test_detects_bidi_in_fixture():
    detector = AdvancedUnicodeDetector()
    with open("tests/fixtures/unicode_bidi.html") as f:
        soup = BeautifulSoup(f.read(), "lxml")
    findings = await detector.detect(soup)
    bidi = [f for f in findings if "Bidi" in f.title]
    assert len(bidi) >= 1
    assert bidi[0].category == "unicode_stego"


@pytest.mark.asyncio
async def test_detects_zalgo_text():
    detector = AdvancedUnicodeDetector()
    with open("tests/fixtures/zalgo_text.html") as f:
        soup = BeautifulSoup(f.read(), "lxml")
    findings = await detector.detect(soup)
    zalgo = [f for f in findings if "Zalgo" in f.title or "Combining" in f.title]
    assert len(zalgo) >= 1


@pytest.mark.asyncio
async def test_clean_page_no_false_positives(sample_clean_html):
    detector = AdvancedUnicodeDetector()
    soup = BeautifulSoup(sample_clean_html, "lxml")
    findings = await detector.detect(soup)
    assert len(findings) == 0
