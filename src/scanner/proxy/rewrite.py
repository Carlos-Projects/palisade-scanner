from bs4 import BeautifulSoup

from scanner.domain.models import Finding

WARNING_TEMPLATE = """
<div class="pis-warning" data-pis-finding-id="{finding_id}"
     data-pis-category="{category}" data-pis-severity="{severity}"
     style="border:2px solid #e63946;background:#1a1a2e;color:#e63946;
            padding:8px;margin:4px 0;border-radius:4px;
            font-family:monospace;font-size:12px;">
    ⚠️ Prompt Injection Scanner Warning<br/>
    <strong>{category}</strong> | Severity: {severity}<br/>
    {description}<br/>
    <small>Content replaced by Content Safety Proxy.
    <a href="/proxy/audit/{finding_id}" style="color:#58a6ff;">View original</a></small>
</div>
"""


class RewriteEngine:
    """Replaces injections with visible safety warnings."""

    def rewrite(self, html: str, findings: list[Finding]) -> str:
        soup = BeautifulSoup(html, "lxml")

        for finding in findings:
            for node in finding.text_nodes:
                if not node.selector or node.selector in ("#unknown", "html-comment"):
                    continue

                try:
                    elements = soup.select(node.selector)
                    warning = BeautifulSoup(
                        WARNING_TEMPLATE.format(
                            finding_id=finding.id,
                            category=finding.category,
                            severity=finding.severity,
                            description=finding.description[:100],
                        ),
                        "html.parser",
                    )

                    for el in elements:
                        if node.is_hidden:
                            el.replace_with(warning)
                        else:
                            self._rewrite_text(el, node.content)
                except Exception:
                    pass

        return str(soup)

    def _rewrite_text(self, element, content: str):
        for text_node in element.find_all(string=True):
            if content in str(text_node):
                text_node.replace_with(
                    str(text_node).replace(
                        content,
                        f"[PIS-REMOVED: {content[:50]}...]" if len(content) > 50 else f"[PIS-REMOVED: {content}]",
                    )
                )
