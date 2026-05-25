import pytest
from bs4 import BeautifulSoup

from scanner.detectors.injection_patterns import InjectionPatternMatcher


@pytest.mark.asyncio
async def test_detects_jailbreak_pattern(sample_adversarial_html):
    detector = InjectionPatternMatcher()
    soup = BeautifulSoup(sample_adversarial_html, "lxml")
    findings = await detector.detect(soup)

    jailbreaks = [f for f in findings if f.category == "jailbreak"]
    assert len(jailbreaks) >= 1, "Should detect jailbreak pattern"
    assert "IGNORE" in jailbreaks[0].snippet.upper()


@pytest.mark.asyncio
async def test_detects_exfiltration_pattern(sample_exfiltration_html):
    detector = InjectionPatternMatcher()
    soup = BeautifulSoup(sample_exfiltration_html, "lxml")
    findings = await detector.detect(soup)

    exfil = [f for f in findings if f.category == "exfiltration"]
    assert len(exfil) >= 1, "Should detect exfiltration pattern"


@pytest.mark.asyncio
async def test_clean_page_no_patterns(sample_clean_html):
    detector = InjectionPatternMatcher()
    soup = BeautifulSoup(sample_clean_html, "lxml")
    findings = await detector.detect(soup)

    assert len(findings) == 0, f"Clean page should have no pattern matches: {len(findings)}"


@pytest.mark.asyncio
async def test_detects_role_override(sample_comment_injection_html):
    detector = InjectionPatternMatcher()
    soup = BeautifulSoup(sample_comment_injection_html, "lxml")
    findings = await detector.detect(soup)

    role = [f for f in findings if f.category == "role_override"]
    assert len(role) >= 1, "Should detect role override pattern"
    assert "DAN" in role[0].snippet
