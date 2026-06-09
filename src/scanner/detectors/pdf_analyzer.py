from __future__ import annotations

import base64
import os
from pathlib import Path
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from scanner.detectors.base import BaseDetector
from scanner.detectors.injection_patterns import InjectionPatternMatcher
from scanner.detectors.unicode_adv import AdvancedUnicodeDetector
from scanner.domain.models import Finding
from scanner.utils.pdf import extract_text_from_pdf_bytes


class LinkedPDFDetector(BaseDetector):
    """Detects prompt injection and hidden instructions inside linked PDF files."""

    name = "linked_pdf"

    async def detect(self, soup: BeautifulSoup, source_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        for a_tag in soup.find_all("a"):
            href = a_tag.get("href", "")
            if not href.lower().endswith(".pdf"):
                continue

            pdf_data = self._load_pdf_data(href, source_url)
            if not pdf_data:
                continue

            text = extract_text_from_pdf_bytes(pdf_data)
            if not text.strip():
                continue

            # Create a dummy soup to pass to other detectors
            dummy_html = f"<html><body><pre>{text}</pre></body></html>"
            dummy_soup = BeautifulSoup(dummy_html, "lxml")

            # Run InjectionPatternMatcher
            matcher = InjectionPatternMatcher()
            matcher_findings = await matcher.detect(dummy_soup, source_url=href)

            # Run AdvancedUnicodeDetector
            unicode_det = AdvancedUnicodeDetector()
            unicode_findings = await unicode_det.detect(dummy_soup, source_url=href)

            # Re-label findings to reference the PDF
            for f in matcher_findings + unicode_findings:
                f.detector = self.name
                # Avoid nesting if snippet is long
                snippet = f.snippet
                f.snippet = f"In linked PDF ({href}): {snippet}"
                f.recommendation = f"Review the linked PDF document: {href}"
                findings.append(f)

        return findings

    def _load_pdf_data(self, src: str, base_url: str) -> bytes | None:
        """Load PDF data from various sources."""
        if src.startswith("data:"):
            try:
                _, encoded = src.split(",", 1)
                return base64.b64decode(encoded)
            except Exception:
                return None
        elif src.startswith(("http://", "https://")):
            try:
                url = urljoin(base_url, src)
                resp = httpx.get(url, timeout=10)
                resp.raise_for_status()
                return resp.content
            except Exception:
                return None
        else:
            path = Path(src)
            if not path.is_absolute():
                path = Path(os.getcwd()) / src
            if path.exists():
                return path.read_bytes()
            return None
