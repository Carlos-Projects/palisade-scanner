import logging

import uvicorn
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse

from scanner.config import Settings
from scanner.pipeline import PipelineOrchestrator
from scanner.proxy import ContentSafetyProxy

logger = logging.getLogger(__name__)


def create_app(mode: str = "strip") -> FastAPI:
    settings = Settings()
    orchestrator = PipelineOrchestrator(settings=settings)
    proxy = ContentSafetyProxy(orchestrator=orchestrator, settings=settings, mode=mode)

    app = FastAPI(title="Content Safety Proxy")

    @app.get("/proxy")
    async def proxy_get(url: str = Query(...), mode: str = Query(None)):
        """Fetch and filter a URL."""
        content, content_type, scan = await proxy.handle(url, mode=mode)
        return HTMLResponse(
            content=content,
            headers={
                "X-Scan-Status": "scanned",
                "X-Risk-Score": str(scan.risk_score),
                "X-Findings-Count": str(len(scan.findings)),
            },
        )

    @app.get("/proxy/audit")
    async def proxy_audit(url: str = Query(...)):
        """Get the scan report for a URL without filtering."""
        report = await orchestrator.scan_url(url)
        return JSONResponse(report.model_dump(mode="json", default=str))

    @app.get("/proxy/status")
    async def proxy_status():
        return {"status": "running", "mode": mode}

    return app


def run_proxy(port: int = 9090, host: str = "127.0.0.1", mode: str = "strip"):
    app = create_app(mode=mode)
    uvicorn.run(app, host=host, port=port, log_level="info")
