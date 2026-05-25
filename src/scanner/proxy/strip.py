from bs4 import BeautifulSoup, Tag

from scanner.domain.models import Finding


class StripEngine:
    """Removes injected elements from HTML while preserving layout."""

    WARNING_COMMENT = " [SAFETY: Injected content removed by Prompt Injection Scanner] "

    def strip(self, html: str, findings: list[Finding]) -> str:
        soup = BeautifulSoup(html, "lxml")

        for finding in findings:
            for node in finding.text_nodes:
                if not node.selector or node.selector in ("#unknown", "html-comment"):
                    continue
                try:
                    elements = soup.select(node.selector)
                    for el in elements:
                        if node.is_hidden or finding.severity in ("critical", "high"):
                            el.decompose()
                        else:
                            self._strip_text(el, node.content)
                except Exception:
                    pass

        return str(soup)

    def _strip_text(self, element: Tag, content: str):
        for text_node in element.find_all(string=True):
            if content in str(text_node):
                text_node.replace_with(
                    str(text_node).replace(content, self.WARNING_COMMENT)
                )
