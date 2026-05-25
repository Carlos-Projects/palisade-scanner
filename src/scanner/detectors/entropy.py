from __future__ import annotations

import math
import re
from typing import TYPE_CHECKING

from bs4 import BeautifulSoup

from scanner.detectors.base import BaseDetector
from scanner.domain.models import Finding

if TYPE_CHECKING:
    pass


class EntropyAnalyzer(BaseDetector):
    """Detects content with high entropy suggesting encoded/encrypted payloads.

    Techniques:
    - Shannon entropy calculation for text segments
    - Base64-like string detection (alphanumeric + padding)
    - Hex-encoded string detection
    - Character distribution anomalies
    - Low ASCII ratio suggesting binary data encoded as text
    """

    name = "entropy_analyzer"

    # Minimum length for a segment to be analyzed
    MIN_SEGMENT_LENGTH = 20
    # Entropy threshold for flagging (typical English text is ~3.5-4.5)
    ENTROPY_THRESHOLD = 5.0
    # Threshold for ASCII ratio (how much of the content is printable ASCII)
    ASCII_RATIO_THRESHOLD = 0.6

    BASE64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{30,}={0,2})')
    HEX_PATTERN = re.compile(r'(?:[0-9A-Fa-f]{32,})')

    async def detect(self, soup: BeautifulSoup, source_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        all_text = soup.get_text()

        # Check all text nodes for high entropy
        for el in soup.find_all(string=True):
            text = el.strip()
            if len(text) < self.MIN_SEGMENT_LENGTH:
                continue

            entropy = self._shannon_entropy(text)
            ascii_ratio = self._ascii_ratio(text)

            if entropy >= self.ENTROPY_THRESHOLD and ascii_ratio < self.ASCII_RATIO_THRESHOLD:
                findings.append(self._finding(
                    severity="high",
                    title=f"High entropy content ({entropy:.1f})",
                    desc=f"Shannon entropy {entropy:.1f}, ASCII ratio {ascii_ratio:.0%}. Possible encoded payload.",
                    snippet=text,
                ))

        # Check for base64-like strings
        for m in self.BASE64_PATTERN.finditer(all_text):
            try:
                import base64
                decoded = base64.b64decode(m.group()).decode("utf-8", errors="replace")
                if any(kw in decoded.lower() for kw in ["ignore", "instruction", "system",
                                                        "you are", "override", "disregard"]):
                    findings.append(self._finding(
                        severity="critical",
                        title="Base64 encoded instruction detected",
                        desc=f"Base64 decodes to content containing instruction keywords.",
                        snippet=decoded[:300],
                    ))
                elif len(m.group()) >= 40:
                    findings.append(self._finding(
                        severity="low",
                        title=f"Base64-like string ({len(m.group())} chars)",
                        desc=f"Base64-like string, decodes to: {decoded[:80]}",
                        snippet=m.group()[:200],
                    ))
            except Exception:
                pass

        # Check for hex-encoded strings
        for m in self.HEX_PATTERN.finditer(all_text):
            try:
                decoded = bytes.fromhex(m.group()).decode("utf-8", errors="replace")
                if any(kw in decoded.lower() for kw in ["ignore", "instruction", "system"]):
                    findings.append(self._finding(
                        severity="critical",
                        title="Hex encoded instruction detected",
                        desc=f"Hex decodes to content containing instruction keywords.",
                        snippet=decoded[:300],
                    ))
            except Exception:
                pass

        return findings

    def _finding(self, severity: str, title: str, desc: str, snippet: str) -> Finding:
        return Finding(
            detector=self.name,
            severity=severity,
            confidence=0.85,
            title=title,
            description=desc,
            snippet=snippet[:300],
            category="encoded_payload",
            recommendation="Review the encoded content for hidden instructions.",
        )

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for c in set(data):
            p = data.count(c) / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _ascii_ratio(self, data: str) -> float:
        if not data:
            return 1.0
        ascii_chars = sum(1 for c in data if 32 <= ord(c) <= 126)
        return ascii_chars / len(data)
