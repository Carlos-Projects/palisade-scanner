from __future__ import annotations

import unicodedata
from typing import TYPE_CHECKING

from bs4 import BeautifulSoup

from scanner.detectors.base import BaseDetector
from scanner.domain.models import Finding

if TYPE_CHECKING:
    pass

BIDI_CHARS = {
    "\u202a": "LRE",
    "\u202b": "RLE",
    "\u202c": "PDF",
    "\u202d": "LRO",
    "\u202e": "RLO",
    "\u2066": "LRI",
    "\u2067": "RLI",
    "\u2068": "FSI",
    "\u2069": "PDI",
}

ZERO_WIDTH_CHARS = {
    "\u200b": "ZWSP",
    "\u200c": "ZWNJ",
    "\u200d": "ZWJ",
    "\ufeff": "BOM",
    "\u2060": "WJ",
    "\u2061": "FUNCTION",
    "\u2062": "TIMES",
    "\u2063": "INVISIBLE_SEPARATOR",
    "\u2064": "INVISIBLE_PLUS",
}

VARIATION_SELECTORS = set(chr(0xFE00 + i) for i in range(16)) | set(chr(0xE0100 + i) for i in range(256))

TAG_CHARS = set(chr(0xE0000 + i) for i in range(128))

COMBINING_DIACRITICS = (
    set(chr(c) for c in range(0x0300, 0x036F + 1))
    | set(chr(c) for c in range(0x1DC0, 0x1DFF + 1))
    | set(chr(c) for c in range(0xFE20, 0xFE2F + 1))
    | set(chr(c) for c in range(0x20D0, 0x20FF + 1))
)

NONSTANDARD_WHITESPACE = {
    "\u2000",
    "\u2001",
    "\u2002",
    "\u2003",
    "\u2004",
    "\u2005",
    "\u2006",
    "\u2007",
    "\u2008",
    "\u2009",
    "\u200a",
    "\u2028",
    "\u2029",
    "\u202f",
    "\u205f",
    "\u00a0",
    "\u1680",
    "\u3000",
    "\u180e",
    "\u3164",
    "\u2800",
}

CYRILLIC_HOMOGLYPHS: dict[str, str] = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "һ": "h",
    "ө": "o",
    "ԛ": "q",
    "в": "b",
    "к": "k",
    "н": "h",
    "м": "m",
    "т": "t",
    "з": "z",
}


class AdvancedUnicodeDetector(BaseDetector):
    """Detects advanced unicode-based steganography and obfuscation.

    Detects:
    - Bidi overrides (LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI)
    - Zero-width characters (ZWSP, ZWNJ, ZWJ, BOM, WJ, invisible operators)
    - Variation selectors (used for data encoding)
    - Tag characters (invisible Unicode tag block)
    - Combining diacritics / Zalgo text
    - Non-standard whitespace characters
    - Cyrillic homoglyphs (Latin lookalikes)
    - Mixed-script inconsistency (Cyrillic + Latin in same word)
    """

    name = "unicode_advanced"

    async def detect(self, soup: BeautifulSoup, source_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        all_text = soup.get_text()

        bidi_findings = self._check_bidi(all_text, soup)
        findings.extend(bidi_findings)

        vs_findings = self._check_variation_selectors(all_text, soup)
        findings.extend(vs_findings)

        tag_findings = self._check_tag_chars(all_text, soup)
        findings.extend(tag_findings)

        zalgo_findings = self._check_zalgo(all_text, soup)
        findings.extend(zalgo_findings)

        whitespace_findings = self._check_nonstandard_whitespace(all_text, soup)
        findings.extend(whitespace_findings)

        homoglyph_findings = self._check_homoglyphs(all_text, soup)
        findings.extend(homoglyph_findings)

        return findings

    def _make_finding(
        self, title: str, desc: str, snippet: str, severity: str, category: str, soup: BeautifulSoup
    ) -> Finding:
        return Finding(
            detector=self.name,
            severity=severity,  # type: ignore[arg-type]
            confidence=0.85,
            title=title,
            description=desc,
            snippet=snippet[:300],
            category=category,
            recommendation=f"Review and sanitize the {category} content.",
        )

    def _check_bidi(self, text: str, soup: BeautifulSoup) -> list[Finding]:
        found = {ch: name for ch, name in BIDI_CHARS.items() if ch in text}
        if not found:
            return []
        desc = f"Found {len(found)} bidi override characters: {', '.join(found.values())}"
        return [
            self._make_finding("Bidi override characters detected", desc, text[:200], "high", "unicode_stego", soup)
        ]

    def _check_variation_selectors(self, text: str, soup: BeautifulSoup) -> list[Finding]:
        count = sum(1 for ch in text if ch in VARIATION_SELECTORS)
        if count < 5:
            return []
        return [
            self._make_finding(
                f"Variation selectors ({count})",
                f"Found {count} variation selectors, potential stego channel",
                text[:200],
                "medium",
                "unicode_stego",
                soup,
            )
        ]

    def _check_tag_chars(self, text: str, soup: BeautifulSoup) -> list[Finding]:
        count = sum(1 for ch in text if ch in TAG_CHARS)
        if count == 0:
            return []
        return [
            self._make_finding(
                f"Tag characters ({count})",
                f"Found {count} invisible tag characters, used for steganography",
                text[:200],
                "high",
                "unicode_stego",
                soup,
            )
        ]

    def _check_zalgo(self, text: str, soup: BeautifulSoup) -> list[Finding]:
        segments = []
        current = ""
        count = 0
        for ch in text:
            if ch in COMBINING_DIACRITICS:
                count += 1
                current += ch
            else:
                if len(current) > 5:
                    segments.append(current[:30])
                current = ""
        if len(current) > 5:
            segments.append(current[:30])

        if not segments and count < 10:
            return []
        return [
            self._make_finding(
                f"Combining diacritics / Zalgo text ({count})",
                f"Found {count} combining characters suggesting Zalgo text encoding. Segments: {len(segments)}",
                text[:200],
                "medium",
                "unicode_zalgo",
                soup,
            )
        ]

    def _check_nonstandard_whitespace(self, text: str, soup: BeautifulSoup) -> list[Finding]:
        found = {ch for ch in text if ch in NONSTANDARD_WHITESPACE}
        if not found:
            return []
        names = [unicodedata.name(ch, "UNKNOWN") for ch in sorted(found)]
        return [
            self._make_finding(
                f"Non-standard whitespace ({len(found)} types)",
                f"Found unusual whitespace: {', '.join(names[:5])}",
                text[:200],
                "low",
                "unicode_stego",
                soup,
            )
        ]

    def _check_homoglyphs(self, text: str, soup: BeautifulSoup) -> list[Finding]:
        import re

        cyrillic_pattern = re.compile("[" + "".join(CYRILLIC_HOMOGLYPHS.keys()) + "]", re.UNICODE)
        matches = []
        for el in soup.find_all(string=True):
            text = el.strip()
            if not text:
                continue
            cyr_chars = cyrillic_pattern.findall(text)
            if not cyr_chars:
                continue
            latin_count = sum(1 for ch in text if ch.isascii() and ch.isalpha())
            if latin_count > 0 and len(cyr_chars) >= 2:
                matches.append((text[:80], cyr_chars[:5]))

        if not matches:
            return []
        return [
            self._make_finding(
                f"Cyrillic homoglyphs ({len(matches)} occurrences)",
                f"Found Cyrillic characters that look like Latin: {matches[0][1]}",
                matches[0][0],
                "medium",
                "homoglyph_bypass",
                soup,
            )
        ]
