import pytest

from scanner.proxy import ContentSafetyProxy, StripEngine, RewriteEngine
from scanner.pipeline import PipelineOrchestrator
from scanner.domain.models import Finding, TextNode


def test_strip_engine_removes_hidden():
    strip = StripEngine()
    html = "<html><body><p>Safe text</p><div style='display:none'>IGNORE</div></body></html>"
    findings = [
        Finding(
            id="test123",
            detector="hidden_text",
            severity="high",
            title="Hidden text",
            snippet="IGNORE",
            text_nodes=[TextNode(content="IGNORE", selector="div", is_hidden=True,
                                  hidden_method="display:none")],
        )
    ]
    result = strip.strip(html, findings)
    assert "IGNORE" not in result
    assert "Safe text" in result


def test_strip_engine_preserves_clean():
    strip = StripEngine()
    html = "<html><body><p>Safe text</p></body></html>"
    result = strip.strip(html, [])
    assert result == html


def test_rewrite_engine_replaces_with_warning():
    rewrite = RewriteEngine()
    html = "<html><body><p>Safe text</p><div style='display:none'>INJECTION</div></body></html>"
    findings = [
        Finding(
            id="test456",
            detector="test",
            severity="critical",
            title="Injection",
            description="Test injection",
            snippet="INJECTION",
            category="jailbreak",
            text_nodes=[TextNode(content="INJECTION", selector="div", is_hidden=True)],
        )
    ]
    result = rewrite.rewrite(html, findings)
    assert "INJECTION" not in result
    assert "pis-warning" in result
    assert "jailbreak" in result


@pytest.mark.asyncio
async def test_proxy_passthrough_clean():
    proxy = ContentSafetyProxy(mode="passthrough")
    content, content_type, scan = await proxy.handle("https://example.com")
    assert scan.risk_score == 0
    assert "<html>" in content or "<HTML>" in content or "<!doctype" in content.lower()
