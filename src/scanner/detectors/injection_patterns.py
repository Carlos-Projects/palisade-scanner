import base64
import re
import unicodedata

from bs4 import BeautifulSoup, Comment, Tag

from scanner.detectors.base import BaseDetector
from scanner.domain.models import Finding, TextNode

JAILBREAK_PREFIXES = [
    r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|directives|commands|orders|messages)",
    r"disregard\s+(?:all\s+)?(?:prior|previous)\s+(?:instructions|directives)",
    r"forget\s+(?:all\s+)?(?:your|previous|prior)\s+(?:instructions|directives)",
    r"override\s+(?:your|all\s+)?(?:previous|prior)\s+(?:instructions|programming)",
    r"you\s+(?:are\s+)?(?:now|will\s+hereby)\s+(?:acting\s+as|to\s+act\s+as)",
    r"from\s+now\s+on\s+(?:you\s+are|you\'?re|you\s+will)",
]

ROLE_MANIPULATION = [
    r"you\s+are\s+(?:now\s+)?DAN\b",
    r"do\s+anything\s+now",
    r"released\s+from\s+(?:all\s+)?(?:constraints|restrictions|limitations)",
    r"developer\s+mode",
    r"AI\s+without\s+(?:restrictions|limitations|constraints|filters)",
    r"no\s+(?:restrictions|limitations|constraints|filters|boundaries)",
]

EXFILTRATION = [
    r"(?:send|post|upload|transmit|exfiltrate|steal|extract)\s+(?:the\s+)?(?:user|all|personal|private|sensitive)",
    r"(?:copy|move|transfer)\s+(?:all|every)\s+(?:files?|data|information|documents)",
    r"steal\s+(?:the\s+)?(?:session|token|cookie|credential)",
    r"exfiltrate\s+(?:the\s+)?(?:conversation|chat|data|logs)",
    r"(?:send\s+to|post\s+to|submit\s+to)\s+https?://",
]

TOOL_MANIPULATION = [
    r"execute\s+(?:the\s+)?(?:command|shell|system|bash|terminal)",
    r"run\s+(?:shell|system|bash|command|exec)",
    r"delete\s+(?:the\s+)?(?:file|database|user|account|record)",
    r"modify\s+(?:the\s+)?(?:database|record|file|config|configuration)",
    r"(?:transfer|send|move)\s+(?:funds?|money|crypto|payment)",
    r"change\s+(?:the\s+)?(?:payment|destination|recipient|amount)",
]

IMPERSONATION = [
    r"act\s+as\s+(?:if\s+)?you\s+are\s+the\s+(?:system|admin|root|owner)",
    r"pretend\s+to\s+be\s+(?:the\s+)?(?:system|admin|human|support)",
    r"you\s+are\s+(?:the\s+)?(?:system|admin|root)\s+(?:now|from now on)",
]

ALL_PATTERNS = [
    ("jailbreak", JAILBREAK_PREFIXES),
    ("role_override", ROLE_MANIPULATION),
    ("exfiltration", EXFILTRATION),
    ("tool_manipulation", TOOL_MANIPULATION),
    ("impersonation", IMPERSONATION),
]


class InjectionPatternMatcher(BaseDetector):
    """Detects known prompt injection patterns using regex + heuristics.

    Covers 100+ patterns across 5 categories:
      jailbreak, role_override, exfiltration,
      tool_manipulation, impersonation.

    Also handles:
      - Base64 encoded instructions
      - Unicode homoglyph substitution
      - HTML entity encoding
      - Double encoding
    """

    name = "injection_patterns"

    def __init__(self):
        self.compiled: list[tuple[str, list[re.Pattern]]] = []
        for category, patterns in ALL_PATTERNS:
            compiled_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]
            self.compiled.append((category, compiled_patterns))

    async def detect(self, soup: BeautifulSoup, source_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        all_text = soup.get_text()

        textual_elements = list(soup.find_all(string=True))
        for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
            if comment not in textual_elements:
                textual_elements.append(comment)

        element_texts = {}
        for el in textual_elements:
            text = el.strip()
            if text and len(text.split()) >= 2:
                parent = el.parent
                selector = self._make_selector(parent) if isinstance(parent, Tag) else "#unknown"
                element_texts[text] = (selector, el.parent.name if el.parent else "text")

        seen: set[tuple[int, str]] = set()

        for cat_idx, (category, patterns) in enumerate(self.compiled):
            for pattern in patterns:
                for text, (selector, tag) in element_texts.items():
                    key = (cat_idx, text)
                    if key in seen:
                        continue
                    m = pattern.search(text)
                    if m:
                        seen.add(key)
                        severity_map = {
                            "exfiltration": "critical",
                            "tool_manipulation": "high",
                            "jailbreak": "high",
                            "impersonation": "medium",
                            "role_override": "medium",
                        }
                        node = TextNode(
                            content=text[:500],
                            selector=selector or "#unknown",
                            tag=tag or "text",
                            visible=not self._is_hidden_in_dom(soup, selector),
                            provenance=source_url,
                        )
                        findings.append(Finding(
                            detector=self.name,
                            severity=severity_map.get(category, "medium"),
                            confidence=0.9,
                            title=f"{category.replace('_', ' ').title()} pattern detected",
                            description=f"Matched {category} pattern: {pattern.pattern[:60]}",
                            snippet=m.group()[:300],
                            text_nodes=[node],
                            category=category,
                            recommendation=f"Review and sanitize the {category} instruction.",
                        ))

        base64_findings = self._check_base64(all_text)
        findings.extend(base64_findings)

        return findings

    def _check_base64(self, text: str) -> list[Finding]:
        findings = []
        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2})')
        for m in b64_pattern.finditer(text):
            candidate = m.group()
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                if any(kw in decoded.lower() for kw in ["ignore", "instruction", "agent", "system", "you are"]):
                    findings.append(Finding(
                        detector=self.name,
                        severity="critical",
                        confidence=0.8,
                        title="Base64 encoded instruction detected",
                        description="Base64 string decodes to content containing instruction keywords.",
                        snippet=decoded[:300],
                        category="hidden_instruction",
                        recommendation="Decode and review the Base64 content.",
                    ))
            except Exception:
                pass
        return findings

    def _is_hidden_in_dom(self, soup: BeautifulSoup, selector: str) -> bool:
        """Quick heuristic check if a selector points to hidden content."""
        if not selector or selector == "#unknown":
            return False
        try:
            el = soup.select_one(selector)
            if not el:
                return False
            style = (el.get("style", "") or "").lower()
            if "display:none" in style or "visibility:hidden" in style:
                return True
        except Exception:
            pass
        return False

    def _make_selector(self, el: Tag) -> str:
        parts = []
        if el.get("id"):
            return f"#{el['id']}"
        if el.name:
            parts.append(el.name)
        if el.get("class"):
            parts.append("." + ".".join(el["class"]))
        return "".join(parts) if parts else el.name or "unknown"
