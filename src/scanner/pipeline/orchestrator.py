import asyncio
import time
from pathlib import Path

from bs4 import BeautifulSoup

from scanner.config import Settings
from scanner.detectors.base import BaseDetector
from scanner.detectors.registry import default_detectors
from scanner.domain.models import Finding, ScanReport
from scanner.domain.scoring import ScoringEngine
from scanner.loaders.base import BaseLoader
from scanner.loaders.pdf import PDFLoader
from scanner.loaders.url import HTMLFileLoader, PasteLoader, URLLoader


class PipelineOrchestrator:
    """Orchestrates the full scan pipeline:

    1. Load content (URL, file, paste)
    2. Run all detectors in parallel
    3. (Optionally) run LLM classifier on findings
    4. Score findings
    5. Generate report
    """

    def __init__(
        self,
        detectors: list[BaseDetector] | None = None,
        settings: Settings | None = None,
    ):
        self.s = settings or Settings()
        self.detectors = detectors or default_detectors(
            llm_provider=self.s.llm_provider,
            llm_model=self.s.llm_model,
            llm_api_key=self.s.llm_api_key,
        )
        self.scoring = ScoringEngine(self.s)
        self.loaders: dict[str, BaseLoader] = {
            "url": URLLoader(timeout_ms=self.s.scan_default_timeout_ms),
            "html": HTMLFileLoader(),
            "paste": PasteLoader(),
            "pdf": PDFLoader(),
        }

    async def scan_url(self, url: str) -> ScanReport:
        content, soup = await self.loaders["url"].load(url)
        return await self._scan(soup, content)

    async def scan_file(self, path: str) -> ScanReport:
        resolved = Path(path).resolve()
        safe = Path(self.s.scan_dir or ".").resolve()
        if safe not in resolved.parents and resolved != safe:
            raise ValueError(f"Path traversal blocked: {path}")
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        loader_key = "pdf" if ext == "pdf" else "html"
        content, soup = await self.loaders[loader_key].load(str(resolved))
        return await self._scan(soup, content)

    async def scan_paste(self, raw: str) -> ScanReport:
        content, soup = await self.loaders["paste"].load(raw)
        return await self._scan(soup, content)

    async def scan_content(self, html: str, url: str = "inline") -> ScanReport:
        soup = BeautifulSoup(html, "lxml")
        return await self._scan(soup, url)

    async def _scan(self, soup: BeautifulSoup, source_url: str) -> ScanReport:
        start = time.monotonic()

        all_findings: list[Finding] = []

        # Phase 1: Run pattern-based detectors
        pattern_detectors = [d for d in self.detectors if d.name != "instruction_classifier"]

        async def _run_detector(detector):
            try:
                return await detector.detect(soup, source_url)
            except Exception as e:
                return [Finding(
                    detector=detector.name,
                    severity="info",
                    confidence=0.0,
                    title=f"Detector error: {detector.name}",
                    description=str(e),
                    category="system_error",
                )]

        results = await asyncio.gather(*[_run_detector(d) for d in pattern_detectors], return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                continue
            all_findings.extend(r)

        # Phase 2: Run LLM classifier on findings (if configured)
        llm_detector = next(
            (d for d in self.detectors if d.name == "instruction_classifier"),
            None,
        )
        if llm_detector and self.s.llm_api_key:
            try:
                enriched = await llm_detector.classify_findings(all_findings)
                enriched_ids = {f.id for f in enriched}
                all_findings = enriched + [f for f in all_findings if f.id not in enriched_ids]
            except Exception as e:
                if self.s.debug:
                    print(f"[LLM] Classification failed: {e}")

        # Score
        risk_score, risk_category = self.scoring.compute(all_findings)
        elapsed = int((time.monotonic() - start) * 1000)

        return ScanReport(
            url=source_url,
            total_findings=len(all_findings),
            risk_score=risk_score,
            risk_category=risk_category,
            findings=all_findings,
            summary=self._generate_summary(risk_score, risk_category, all_findings),
            scan_time_ms=elapsed,
        )

    def _generate_summary(self, score: int, category: str, findings: list[Finding]) -> str:
        if not findings:
            return "No threats detected."
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        return (
            f"Risk score: {score}/100 ({category}). "
            f"Found {len(findings)} issues: "
            f"{critical} critical, {high} high, {medium} medium."
        )
