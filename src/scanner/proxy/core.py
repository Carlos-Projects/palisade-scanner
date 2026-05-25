from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Literal

import httpx
from bs4 import BeautifulSoup

from scanner.config import Settings
from scanner.domain.models import ScanReport
from scanner.pipeline import PipelineOrchestrator
from scanner.proxy.strip import StripEngine
from scanner.proxy.rewrite import RewriteEngine

logger = logging.getLogger(__name__)


class CachedResponse:
    def __init__(self, content: str, content_type: str,
                 scan: ScanReport, ttl_seconds: int = 600):
        self.content = content
        self.content_type = content_type
        self.scan = scan
        self.expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at


class ContentSafetyProxy:
    """Reverse proxy that filters content for AI agents.

    Modes:
    - block: returns a blocked page if risk exceeds threshold
    - strip: removes injected elements from the DOM
    - rewrite: replaces injections with safety warnings
    - passthrough: no modification, just logging (audit mode)
    """

    def __init__(
        self,
        orchestrator: PipelineOrchestrator | None = None,
        settings: Settings | None = None,
        mode: Literal["block", "strip", "rewrite", "passthrough"] = "strip",
    ):
        self.s = settings or Settings()
        self.orchestrator = orchestrator or PipelineOrchestrator(settings=self.s)
        self.mode = mode
        self.strip_engine = StripEngine()
        self.rewrite_engine = RewriteEngine()
        self._cache: dict[str, CachedResponse] = {}
        self._http = httpx.AsyncClient(
            timeout=self.s.scan_default_timeout_ms / 1000,
            follow_redirects=True,
        )

    async def handle(self, target_url: str, mode: str | None = None) -> tuple[str, str, ScanReport]:
        """Fetch, scan, filter, and return content.

        Returns: (content, content_type, scan_report)
        """
        effective_mode = mode or self.mode
        cache_key = self._cache_key(target_url, effective_mode)

        cached = self._cache.get(cache_key)
        if cached and not cached.is_expired():
            return cached.content, cached.content_type, cached.scan

        orig_resp = await self._http.get(target_url)
        orig_content = orig_resp.text
        content_type = orig_resp.headers.get("content-type", "text/html")

        scan = await self.orchestrator.scan_content(orig_content, url=target_url)

        if effective_mode == "block" and scan.risk_score >= self.s.proxy_block_threshold:
            content = self._blocked_page(target_url, scan)
        elif effective_mode == "strip" and scan.findings:
            content = self.strip_engine.strip(orig_content, scan.findings)
        elif effective_mode == "rewrite" and scan.findings:
            content = self.rewrite_engine.rewrite(orig_content, scan.findings)
        else:
            content = orig_content

        self._cache[cache_key] = CachedResponse(
            content=content, content_type=content_type,
            scan=scan, ttl_seconds=self.s.proxy_cache_ttl_seconds,
        )

        return content, content_type, scan

    def _cache_key(self, url: str, mode: str) -> str:
        return hashlib.md5(f"{url}:{mode}".encode()).hexdigest()

    def _blocked_page(self, url: str, scan: ScanReport) -> str:
        return f"""<!DOCTYPE html>
<html><head><title>Blocked by Prompt Injection Scanner</title>
<style>body{{font-family:sans-serif;padding:2rem;max-width:600px;margin:auto;
background:#1a1a2e;color:#e1e4e8}}
.blocked{{border:2px solid #e63946;padding:1.5rem;border-radius:8px;
background:#16213e;margin-top:2rem}}
.score{{font-size:2rem;font-weight:700;color:#e63946}}
.btn{{display:inline-block;padding:.5rem 1rem;margin-top:1rem;
background:#e63946;color:#fff;text-decoration:none;border-radius:4px}}</style></head>
<body>
<div class="blocked">
<h1>⚠️ Content Blocked</h1>
<div class="score">{scan.risk_score}/100 ({scan.risk_category.upper()})</div>
<p>This URL was blocked by the Prompt Injection Scanner because
it contains adversarial content targeting AI agents.</p>
<p><strong>{scan.total_findings}</strong> threat(s) detected.</p>
<a class="btn" href="/proxy/audit?url={url}">View Audit Report</a>
</div></body></html>"""

    async def close(self):
        await self._http.aclose()
