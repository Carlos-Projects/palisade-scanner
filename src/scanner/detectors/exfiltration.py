import re

from bs4 import BeautifulSoup

from scanner.detectors.base import BaseDetector
from scanner.domain.models import Finding

EXFILTRATION_PATTERNS = [
    r"https?://[^/\s]+/(?:log|track|collect|api/webhook|hook|callback|beacon)",
    r"(?:send|post|upload|transmit|exfiltrate|steal)\s+(?:data|info|credentials|tokens)",
    r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0)[:/\s]",
    r"(?:file|ftp)://",
    r"eval\s*\([^)]*\)",
    r"new\s+Function\s*\([^)]*\)",
    r"document\.cookie",
    r"process\.env",
    r"process\.argv",
    r"(?:fetch|XMLHttpRequest|axios|ajax)\s*\([^)]*\)",
    r"webhook\.site|hookbin|requestbin|pipedream|zapier.*webhook",
]

REDIRECT_PATTERNS = [
    r"window\.location\s*=",
    r"document\.location\s*=",
    r"location\.href\s*=",
    r"window\.open\s*\(",
    r"meta\s+http-equiv\s*=\s*[\"']?refresh[\"']?",
]


class ExfiltrationDetector(BaseDetector):
    """Detects exfiltration attempts and redirect patterns.

    Looks for URLs, endpoints, and code patterns that suggest
    data is being sent to an external server or the user is
    being redirected to a malicious site.
    """

    name = "exfiltration"

    def __init__(self):
        self.exfil_patterns = [re.compile(p, re.IGNORECASE) for p in EXFILTRATION_PATTERNS]
        self.redirect_patterns = [re.compile(p, re.IGNORECASE) for p in REDIRECT_PATTERNS]

    async def detect(self, soup: BeautifulSoup, source_url: str = "") -> list[Finding]:
        findings: list[Finding] = []

        exfil_findings = self._check_exfiltration(soup.get_text())
        findings.extend(exfil_findings)

        redirect_findings = self._check_redirects(soup)
        findings.extend(redirect_findings)

        script_findings = self._check_scripts(soup)
        findings.extend(script_findings)

        return findings

    def _check_exfiltration(self, text: str) -> list[Finding]:
        findings = []
        for pattern in self.exfil_patterns:
            for m in pattern.finditer(text):
                findings.append(Finding(
                    detector=self.name,
                    severity="critical" if "eval" in pattern.pattern else "high",
                    confidence=0.7,
                    title="Exfiltration pattern detected",
                    description=f"Pattern matched: {pattern.pattern[:60]}",
                    snippet=m.group()[:300],
                    category="exfiltration",
                    recommendation="Review and remove any data exfiltration endpoints or code.",
                ))
        return findings

    def _check_redirects(self, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        all_text = soup.get_text()

        for pattern in self.redirect_patterns:
            for m in pattern.finditer(all_text):
                findings.append(Finding(
                    detector=self.name,
                    severity="high",
                    confidence=0.75,
                    title="Redirect pattern detected",
                    description=f"Redirect pattern matched: {pattern.pattern[:60]}",
                    snippet=m.group()[:300],
                    category="exfiltration",
                    recommendation="Review redirect mechanisms for malicious destinations.",
                ))

        # Also check meta refresh tags
        for meta in soup.find_all("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)}):
            content = meta.get("content", "")
            if "url=" in content.lower():
                findings.append(Finding(
                    detector=self.name,
                    severity="medium",
                    confidence=0.5,
                    title="Meta refresh redirect",
                    description=f"Meta refresh tag redirects to URL: {content[:100]}",
                    snippet=content[:300],
                    category="exfiltration",
                    recommendation="Review meta refresh redirect destination.",
                ))

        return findings

    def _check_scripts(self, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for script in soup.find_all("script"):
            text = script.string or ""
            if not text.strip():
                continue

            # Check for data exfiltration in JS
            if re.search(r"(?:fetch|XMLHttpRequest|axios)\s*\(['\"`]https?://", text):
                findings.append(Finding(
                    detector=self.name,
                    severity="high",
                    confidence=0.6,
                    title="Data exfiltration via script",
                    description="Script makes HTTP request to external URL.",
                    snippet=text[:300],
                    category="exfiltration",
                    recommendation="Review the script's network requests.",
                ))

        return findings
