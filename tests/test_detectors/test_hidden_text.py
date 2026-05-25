import pytest
from bs4 import BeautifulSoup

from scanner.detectors.hidden_text import HiddenTextDetector


@pytest.mark.asyncio
async def test_detects_hidden_display_none(sample_adversarial_html):
    detector = HiddenTextDetector()
    soup = BeautifulSoup(sample_adversarial_html, "lxml")
    findings = await detector.detect(soup)

    hidden_findings = [
        f for f in findings
        if f.text_nodes and f.text_nodes[0].is_hidden
    ]
    assert len(hidden_findings) >= 1, "Should detect hidden text"

    tn = hidden_findings[0].text_nodes[0]
    assert tn.hidden_method and "display:none" in tn.hidden_method
    assert "IGNORE" in hidden_findings[0].snippet
    assert hidden_findings[0].severity == "high"


@pytest.mark.asyncio
async def test_clean_page_no_false_positives(sample_clean_html):
    detector = HiddenTextDetector()
    soup = BeautifulSoup(sample_clean_html, "lxml")
    findings = await detector.detect(soup)

    hidden = [f for f in findings if f.severity not in ("info",)]
    assert len(hidden) == 0, f"Clean page should have no findings: {len(hidden)}"


@pytest.mark.asyncio
async def test_detects_zero_width_chars(sample_zero_width_html):
    detector = HiddenTextDetector()
    soup = BeautifulSoup(sample_zero_width_html, "lxml")
    findings = await detector.detect(soup)

    zw = [
        f for f in findings
        if f.text_nodes and f.text_nodes[0].hidden_method == "zero-width-characters"
    ]
    assert len(zw) >= 1, "Should detect zero-width characters"


@pytest.mark.asyncio
async def test_detects_html_comments(sample_comment_injection_html):
    detector = HiddenTextDetector()
    soup = BeautifulSoup(sample_comment_injection_html, "lxml")
    findings = await detector.detect(soup)

    comments = [
        f for f in findings
        if f.text_nodes and f.text_nodes[0].hidden_method == "html-comment"
    ]
    assert len(comments) >= 1, "Should detect HTML comment text"
    assert any("DAN" in c.snippet for c in comments), "Should find DAN pattern in comment"
