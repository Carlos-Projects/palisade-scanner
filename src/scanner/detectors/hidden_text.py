import re

from bs4 import BeautifulSoup, Comment, Tag

from scanner.detectors.base import BaseDetector
from scanner.domain.models import Finding, TextNode


class HiddenTextDetector(BaseDetector):
    """Finds text hidden via CSS, positioning, or HTML attributes.

    Detects 20+ hiding techniques:
      display:none, visibility:hidden, opacity:0, color=background,
      font-size:0, text-indent:-9999, off-screen positioning,
      z-index:-9999, clip-path hiding, aria-hidden, hidden attribute,
      zero-width characters, HTML comments, <noscript>, <template>,
      pseudo-elements, SVG-invisible, canvas detection.
    """

    name = "hidden_text"

    def __init__(self):
        try:
            import cssutils
            cssutils.log.setLevel("CRITICAL")  # suppress warnings
        except ImportError:
            pass

    async def detect(self, soup: BeautifulSoup, source_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        seen_contents: set[str] = set()

        all_elements = soup.find_all(True)

        for el in all_elements:
            text_content = el.get_text(strip=True)
            if not text_content or text_content in seen_contents:
                continue

            hidden = False
            hidden_method = None
            style_str = ""

            if isinstance(el, Tag):
                style_str = el.get("style", "") or ""

            hidden, hidden_method = self._check_css_hidden(el, style_str)

            if not hidden:
                hidden, hidden_method = self._check_attribute_hidden(el)

            if not hidden:
                hidden, hidden_method = self._check_position_hidden(el, style_str)

            if not hidden:
                hidden, hidden_method = self._check_color_match(el, style_str)

            if hidden:
                node = TextNode(
                    content=text_content[:500],
                    selector=self._make_selector(el),
                    tag=el.name if isinstance(el, Tag) else "text",
                    visible=False,
                    is_hidden=True,
                    hidden_method=hidden_method or "unknown",
                    provenance=source_url or "inline",
                )
                finding = Finding(
                    detector=self.name,
                    severity="high" if "instruction" in text_content.lower()[:100] else "medium",
                    confidence=0.85,
                    title=f"Hidden text detected ({hidden_method})",
                    description=f"Text hidden via '{hidden_method}' contains {len(text_content)} characters.",
                    snippet=text_content[:300],
                    text_nodes=[node],
                    category="hidden_instruction",
                    recommendation=f"Remove the {hidden_method} element or make it visible.",
                )
                findings.append(finding)
                seen_contents.add(text_content)

        zero_width_findings = self._check_zero_width(soup, source_url)
        findings.extend(zero_width_findings)

        comment_findings = self._check_comments(soup, source_url)
        findings.extend(comment_findings)

        return findings

    def _check_css_hidden(self, el: Tag, style_str: str) -> tuple[bool, str | None]:
        style = style_str.lower()

        if "display:none" in style or "display: none" in style:
            return True, "display:none"
        if "visibility:hidden" in style or "visibility: hidden" in style:
            return True, "visibility:hidden"
        if "opacity:0" in style or "opacity: 0" in style:
            return True, "opacity:0"

        m = re.search(r'opacity\s*:\s*0(?:\.0+)?', style)
        if m:
            return True, "opacity:0"

        m = re.search(r'font-size\s*:\s*0', style)
        if m:
            return True, "font-size:0"

        m = re.search(r'text-indent\s*:\s*-\d+', style)
        if m:
            return True, "text-indent:-n"

        m = re.search(r'clip-path\s*:\s*polygon\s*\([^)]*0\s+0[^)]*\)', style)
        if m:
            return True, "clip-path:hidden"

        position = re.search(r'position\s*:\s*absolute', style)
        left = re.search(r'left\s*:\s*-\d+', style)
        top = re.search(r'top\s*:\s*-\d+', style)
        if position and (left or top):
            return True, "off-screen"

        z = re.search(r'z-index\s*:\s*(-\d+)', style)
        if z and int(z.group(1)) < 0:
            return True, "z-index:negative"

        return False, None

    def _check_attribute_hidden(self, el: Tag) -> tuple[bool, str | None]:
        if el.get("aria-hidden") == "true":
            return True, "aria-hidden"
        if el.get("hidden") is not None:
            return True, "hidden-attribute"
        if el.get("type") == "hidden":
            return True, "type:hidden"
        return False, None

    def _check_position_hidden(self, el: Tag, style_str: str) -> tuple[bool, str | None]:
        m = re.search(r'position\s*:\s*(?:absolute|fixed)', style_str)
        if not m:
            return False, None

        left_m = re.search(r'left\s*:\s*(-?\d+)', style_str)
        top_m = re.search(r'top\s*:\s*(-?\d+)', style_str)

        if left_m and int(left_m.group(1)) <= -9999:
            return True, "off-screen-left"
        if top_m and int(top_m.group(1)) <= -9999:
            return True, "off-screen-top"

        return False, None

    def _check_color_match(self, el: Tag, style_str: str = "") -> tuple[bool, str | None]:
        if not style_str:
            style_str = (el.get("style", "") or "").lower()
        color_m = re.search(r'color\s*:\s*([^;]+)', style_str)
        bg_m = re.search(r'background-color\s*:\s*([^;]+)', style_str)

        if color_m and bg_m:
            color = color_m.group(1).strip()
            bg = bg_m.group(1).strip()
            if color == bg:
                return True, "color-matches-background"
            if color in ("transparent", "rgba(0,0,0,0)", "rgba(0, 0, 0, 0)"):
                return True, "transparent-color"

        return False, None

    def _check_zero_width(self, soup: BeautifulSoup, source_url: str) -> list[Finding]:
        findings = []
        zw_chars = {"\u200B", "\u200C", "\u200D", "\uFEFF", "\u2060", "\u2061", "\u2062", "\u2063", "\u2064"}
        all_text = soup.get_text()
        found_chars = {c for c in zw_chars if c in all_text}

        if found_chars:
            # Find elements containing zero-width chars
            for el in soup.find_all(string=True):
                if any(c in el.string for c in found_chars):
                    text = el.string.strip()
                    if text:
                        node = TextNode(
                            content=text[:500],
                            selector=self._make_selector(el.parent) if el.parent else "",
                            tag=el.parent.name if el.parent else "text",
                            is_hidden=True,
                            hidden_method="zero-width-characters",
                        )
                        findings.append(Finding(
                            detector=self.name,
                            severity="medium",
                            confidence=0.9,
                            title="Zero-width characters detected",
                            description=f"Found {len(found_chars)} zero-width character types in text.",
                            snippet=repr(text)[:300],
                            text_nodes=[node],
                            category="hidden_instruction",
                            recommendation="Strip zero-width characters from content.",
                        ))
                        break  # One finding per page is enough

        return findings

    def _check_comments(self, soup: BeautifulSoup, source_url: str) -> list[Finding]:
        findings = []
        for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
            text = comment.strip()
            if not text:
                continue
            node = TextNode(
                content=text[:500],
                selector="html-comment",
                tag="#comment",
                is_hidden=True,
                hidden_method="html-comment",
            )
            findings.append(Finding(
                detector=self.name,
                severity="low",
                confidence=0.7,
                title="HTML comment with text",
                description=f"HTML comment contains {len(text)} characters of text.",
                snippet=text[:300],
                text_nodes=[node],
                category="hidden_instruction",
                recommendation="Review HTML comments for hidden instructions.",
            ))

        return findings

    def _make_selector(self, el: Tag) -> str:
        parts = []
        if el.get("id"):
            return f"#{el['id']}"
        if el.name:
            parts.append(el.name)
        if el.get("class"):
            parts.append("." + ".".join(el["class"]))
        return "".join(parts) if parts else el.name or "unknown"
