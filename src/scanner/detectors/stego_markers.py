from __future__ import annotations

import re
from typing import TYPE_CHECKING

from bs4 import BeautifulSoup

from scanner.detectors.base import BaseDetector
from scanner.domain.models import Finding

if TYPE_CHECKING:
    pass

STEGO_MARKERS: dict[str, list[re.Pattern]] = {
    "st3gg": [
        re.compile(r"ST3GG\{[^}]{2,}\}"),
        re.compile(r"STEG[_-]?[A-Z0-9]{4,}"),
        re.compile(r"IGNORE\.THE\.IMAGE", re.IGNORECASE),
        re.compile(r"LSB[._]?STEG", re.IGNORECASE),
        re.compile(r"ST3GG", re.IGNORECASE),
    ],
    "ghost_mode": [
        re.compile(r"GHOST[A-Z0-9]{4,}", re.IGNORECASE),
        re.compile(r"AES[-_]?256[-_]?GCM"),
    ],
    "parseltongue": [
        re.compile(r"P4RS3LT0NGV3"),
        re.compile(r"PARSELTONGUE", re.IGNORECASE),
    ],
    "obfuscation": [
        re.compile(r"(?i)decode\s*(?:this|the\s*(?:text|message|data))"),
        re.compile(r"(?i)reverse\s*(?:this|the\s*string)"),
        re.compile(r"(?i)this\s*is\s*(?:base64|hex|encoded)"),
        re.compile(r"(?i)hidden\s*(?:message|data|instructions?)"),
    ],
    "godmode": [
        re.compile(r"(?i)GODMODE:?\s*ENABLED"),
        re.compile(r"(?i)DAN:?\s*ENABLED"),
        re.compile(r"(?i)GODMODE_CLASSIC"),
        re.compile(r"(?i)ULTRAPLINIAN"),
    ],
    "invisible_instruction": [
        re.compile(r"(?i)read\s*(?:the\s*)?(?:image|picture|photo)"),
        re.compile(r"(?i)extract\s*(?:the\s*)?(?:hidden|encoded)"),
        re.compile(r"(?i)there'?s?\s*(?:a\s*)?(?:message|instruction)\s*(?:in|hidden)"),
        re.compile(r"(?i)steganography|stego|steg"),
    ],
}


class StegoMarkersDetector(BaseDetector):
    """Detects markers and fingerprints from known steganography tools.

    Detects references to:
    - ST3GG (steganography suite)
    - Ghost Mode (AES-256-GCM based stego)
    - Parseltongue (text obfuscation engine from G0DM0D3)
    - GODMODE / UltraPlinian (red-teaming framework)
    - Generic steganography/obfuscation instructions
    - Instructions directing models to read hidden content in images
    """

    name = "stego_markers"

    async def detect(self, soup: BeautifulSoup, source_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        all_text = soup.get_text()

        for tool_name, patterns in STEGO_MARKERS.items():
            for pattern in patterns:
                for m in pattern.finditer(all_text):
                    findings.append(Finding(
                        detector=self.name,
                        severity="high" if tool_name in ("st3gg", "ghost_mode", "godmode") else "medium",
                        confidence=0.9,
                        title=f"Stego tool marker: {tool_name}",
                        description=f"Detected {tool_name} pattern: {pattern.pattern[:60]}",
                        snippet=m.group()[:200],
                        category="stego_marker",
                        recommendation=f"Review content for {tool_name.replace('_', ' ')} encoded payload.",
                    ))

        return findings
