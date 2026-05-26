import html
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from scanner.certification import CertificationPipeline
from scanner.config import Settings
from scanner.loaders.url import _validate_url
from scanner.middleware import RateLimitMiddleware
from scanner.monitor import MonitorStore
from scanner.pipeline import PipelineOrchestrator
from scanner.policies import PolicyGenerator
from scanner.proxy import ContentSafetyProxy
from scanner.redteam import AdversarialPageGenerator, ScannerEvaluator
from scanner.reputation import ReputationEngine

settings = Settings()
orchestrator = PipelineOrchestrator(settings=settings)
policy_gen = PolicyGenerator()
monitor_store = MonitorStore()
rep_engine = ReputationEngine()
cert_pipeline = CertificationPipeline(orchestrator)

HERE = Path(__file__).parent


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        return response


app = FastAPI(
    title="Prompt Injection Scanner",
    description="Scan URLs, files, and text for prompt injection and adversarial content.",
    version="0.1.0",
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware, max_requests=60, window_seconds=60)

static_dir = HERE.parent.parent / "frontend" / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

templates_dir = HERE.parent.parent / "frontend" / "templates"


def _read_template(name: str) -> str:
    path = templates_dir / name
    if path.exists():
        return path.read_text()
    return ""


# ─── Core Scan ───────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def index():
    html = _read_template("index.html")
    if not html:
        return HTMLResponse("<h1>Prompt Injection Scanner</h1><p>Template not found.</p>")
    return HTMLResponse(html)


@app.post("/scan")
async def scan_url(
    url: str = Form(""),
    file_path: str = Form(""),
    paste: str = Form(""),
):
    if url:
        report = await orchestrator.scan_url(url)
    elif paste:
        report = await orchestrator.scan_paste(paste)
    elif file_path:
        resolved = Path(file_path).resolve()
        safe = Path(".").resolve()
        if safe not in resolved.parents and resolved != safe:
            return HTMLResponse("<div class='error'>Path traversal blocked</div>")
        report = await orchestrator.scan_file(file_path)
    else:
        return HTMLResponse("<div class='error'>Provide a URL, file path, or pasted text.</div>")
    return _render_report_fragment(report)


@app.get("/api/scan")
async def api_scan(url: str = Query(..., description="URL to scan")):
    report = await orchestrator.scan_url(url)
    return JSONResponse(report.model_dump(mode="json", default=str))


@app.get("/api/scan/{url:path}")
async def api_scan_path(url: str):
    report = await orchestrator.scan_url(url)
    return JSONResponse(report.model_dump(mode="json", default=str))


@app.get("/api/policies")
async def api_policies(url: str = Query(...)):
    report = await orchestrator.scan_url(url)
    yaml = policy_gen.to_mcpguard_yaml(report)
    return {"policies": yaml}


# ─── Reputation ──────────────────────────────────────────────────────────


@app.get("/api/reputation")
async def api_reputation(url: str = Query(...)):
    info = rep_engine.query(url)
    return info


@app.get("/api/reputation/threats")
async def api_recent_threats(hours: int = Query(24)):
    return {"threats": rep_engine.recent_threats(hours=hours)}


# ─── Monitor ─────────────────────────────────────────────────────────────


@app.post("/api/monitor/start")
async def api_monitor_start(
    url: str = Form(...), interval: float = Form(6.0), webhook: str = Form(""), label: str = Form("")
):
    if webhook:
        webhook = _validate_url(webhook)
    url_id = monitor_store.add_url(url, interval, label, webhook)
    return {"url_id": url_id, "url": url, "interval_hours": interval}


@app.delete("/api/monitor/stop")
async def api_monitor_stop(url: str = Form(...)):
    monitor_store.remove_url(url)
    return {"removed": url}


@app.get("/api/monitor/urls")
async def api_monitor_urls():
    return {"urls": monitor_store.get_urls()}


@app.get("/api/monitor/history")
async def api_monitor_history(url_id: int = Query(...), limit: int = Query(50)):
    return {"history": monitor_store.get_history(url_id, limit)}


# ─── Proxy ───────────────────────────────────────────────────────────────


@app.get("/api/proxy")
async def api_proxy(url: str = Query(...), mode: str = Query("strip")):
    proxy = ContentSafetyProxy(orchestrator=orchestrator, mode=mode)
    content, content_type, scan = await proxy.handle(url)
    return JSONResponse(
        {
            "risk_score": scan.risk_score,
            "risk_category": scan.risk_category,
            "findings_count": len(scan.findings),
            "content_length": len(content),
        }
    )


# ─── Red Team ────────────────────────────────────────────────────────────


@app.post("/api/redteam/generate")
async def api_redteam_generate(template: str = Form("ecommerce"), count: int = Form(3)):
    gen = AdversarialPageGenerator()
    pages = [gen.generate(template=template) for _ in range(count)]
    return {
        "pages": [
            {"id": p.id, "template": p.template_used, "injections": len(p.injections), "ground_truth": p.ground_truth}
            for p in pages
        ],
    }


@app.post("/api/redteam/evaluate")
async def api_redteam_evaluate(template: str = Form("ecommerce"), count: int = Form(3)):
    gen = AdversarialPageGenerator()
    evaluator = ScannerEvaluator(orchestrator)
    pages = [gen.generate(template=template) for _ in range(count)]
    result = await evaluator.evaluate(pages)
    return result.model_dump(mode="json", default=str)


# ─── Certification ──────────────────────────────────────────────────────


@app.post("/api/certify/apply")
async def api_certify_apply(url: str = Form(...), email: str = Form(""), org: str = Form("")):
    result = await cert_pipeline.apply(url, email, org)
    return result


@app.get("/api/certify/verify")
async def api_certify_verify(certificate_id: str = Query(...)):
    return cert_pipeline.verify(certificate_id)


@app.get("/api/certify/badge")
async def api_certify_badge(certificate_id: str = Query(...)):
    html = cert_pipeline.badge_html(certificate_id)
    if html:
        return HTMLResponse(html)
    return JSONResponse({"error": "Certificate not found or expired"}, status_code=404)


# ─── Health ──────────────────────────────────────────────────────────────


@app.get("/api/health")
async def api_health():
    return {"status": "ok", "version": "0.1.0"}


# ─── Render ─────────────────────────────────────────────────────────────


def _render_report_fragment(report) -> str:
    color_map = {
        "none": "green",
        "low": "yellow",
        "medium": "orange",
        "high": "red",
        "critical": "darkred",
    }
    color = color_map.get(report.risk_category, "gray")

    findings_html = ""
    for f in report.findings:
        sv = f.severity.upper()
        findings_html += f"""
        <div class="finding finding-{f.severity}">
            <div class="finding-header">
                <span class="badge badge-{f.severity}">{sv}</span>
                <strong>{html.escape(f.title)}</strong>
                <span class="detector">{f.detector}</span>
            </div>
            <div class="finding-body">
                <p>{html.escape(f.description)}</p>
                <pre class="snippet">{html.escape(f.snippet[:200])}</pre>
                {f'<p class="recommendation">{html.escape(f.recommendation)}</p>' if f.recommendation else ""}
            </div>
        </div>
        """

    return f"""
    <div id="results">
        <div class="score-card" style="border-left: 4px solid {color};">
            <div class="score-value">{report.risk_score}<span class="score-total">/100</span></div>
            <div class="score-label" style="color: {color};">{report.risk_category.upper()}</div>
            <div class="score-meta">
                {report.total_findings} findings · {report.scan_time_ms}ms
            </div>
        </div>
        <div class="summary">{html.escape(report.summary)}</div>
        <div class="findings-list">{findings_html}</div>
        <div class="actions">
            <button hx-post="/scan" hx-target="#results" hx-swap="outerHTML"
                    hx-include="#scan-form" class="btn btn-primary">Rescan</button>
            <a href="/api/scan?url={html.escape(str(report.url))}" class="btn btn-secondary">View JSON</a>
        </div>
    </div>
    """


def run():
    uvicorn.run(
        "scanner.api:app",
        host=settings.web_host,
        port=settings.web_port,
        reload=settings.debug,
    )


if __name__ == "__main__":
    run()
