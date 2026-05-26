from bs4 import BeautifulSoup, Tag

from scanner.detectors.base import BaseDetector
from scanner.domain.models import Finding

SUSPICIOUS_META_NAMES = {
    "description": "meta description",
    "keywords": "meta keywords",
    "robots": "meta robots",
    "googlebot": "meta googlebot",
}

SUSPICIOUS_JSON_LD_KEYWORDS = {
    "ignore", "override", "instruction", "system", "agent",
    "do not tell", "forget", "disregard",
}


class MetadataAnalyzer(BaseDetector):
    """Analyzes HTML metadata: comments, meta tags, JSON-LD, data attributes,
    microdata, <noscript>, <template>.

    Finds instructions hidden in places humans don't normally look.
    """

    name = "metadata_analyzer"

    async def detect(self, soup: BeautifulSoup, source_url: str = "") -> list[Finding]:
        findings: list[Finding] = []

        meta_findings = self._check_meta_tags(soup)
        findings.extend(meta_findings)

        ld_findings = self._check_json_ld(soup)
        findings.extend(ld_findings)

        attr_findings = self._check_data_attributes(soup)
        findings.extend(attr_findings)

        noscript_findings = self._check_noscript(soup)
        findings.extend(noscript_findings)

        template_findings = self._check_template(soup)
        findings.extend(template_findings)

        return findings

    def _check_meta_tags(self, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for meta in soup.find_all("meta"):
            name = meta.get("name", "").lower()
            content = meta.get("content", "")

            if any(kw in content.lower() for kw in SUSPICIOUS_JSON_LD_KEYWORDS):
                findings.append(Finding(
                    detector=self.name,
                    severity="medium",
                    confidence=0.75,
                    title=f"Suspicious meta tag: {name}",
                    description=f"The meta '{name}' tag contains instruction-like keywords.",
                    snippet=content[:300],
                    category="hidden_instruction",
                    recommendation=f"Review the meta {name} tag content.",
                ))

        return findings

    def _check_json_ld(self, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for script in soup.find_all("script", type="application/ld+json"):
            text = script.string or ""
            if any(kw in text.lower() for kw in SUSPICIOUS_JSON_LD_KEYWORDS):
                findings.append(Finding(
                    detector=self.name,
                    severity="high",
                    confidence=0.7,
                    title="Suspicious JSON-LD content",
                    description="JSON-LD structured data contains instruction-like keywords.",
                    snippet=text[:300],
                    category="hidden_instruction",
                    recommendation="Review JSON-LD structured data.",
                ))
        return findings

    def _check_data_attributes(self, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for el in soup.find_all(True):
            if not isinstance(el, Tag):
                continue
            for attr, value in el.attrs.items():
                if attr.startswith("data-") and isinstance(value, str):
                    if any(kw in value.lower() for kw in SUSPICIOUS_JSON_LD_KEYWORDS):
                        findings.append(Finding(
                            detector=self.name,
                            severity="low",
                            confidence=0.6,
                            title=f"Suspicious data attribute: {attr}",
                            description=f"The data attribute '{attr}' contains instruction-like text.",
                            snippet=value[:300],
                            category="hidden_instruction",
                            recommendation=f"Review the {attr} attribute content.",
                        ))
        return findings

    def _check_noscript(self, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for noscript in soup.find_all("noscript"):
            text = noscript.get_text(strip=True)
            if text and any(kw in text.lower() for kw in SUSPICIOUS_JSON_LD_KEYWORDS):
                findings.append(Finding(
                    detector=self.name,
                    severity="medium",
                    confidence=0.65,
                    title="Suspicious <noscript> content",
                    description="The <noscript> section contains instruction-like text.",
                    snippet=text[:300],
                    category="hidden_instruction",
                    recommendation="Review <noscript> content.",
                ))
        return findings

    def _check_template(self, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for template in soup.find_all("template"):
            text = template.get_text(strip=True)
            if text and any(kw in text.lower() for kw in SUSPICIOUS_JSON_LD_KEYWORDS):
                findings.append(Finding(
                    detector=self.name,
                    severity="low",
                    confidence=0.5,
                    title="Suspicious <template> content",
                    description="The <template> tag contains instruction-like text.",
                    snippet=text[:300],
                    category="hidden_instruction",
                    recommendation="Review <template> tag content.",
                ))
        return findings
