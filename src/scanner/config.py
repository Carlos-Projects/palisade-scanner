from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "PIS_", "env_file": ".env", "extra": "ignore"}

    debug: bool = False
    data_dir: Path = Path.home() / ".pis"

    scan_dir: str = "."  # safe directory for file scanning; "." = current working dir
    scan_default_timeout_ms: int = 30_000
    scan_max_urls_batch: int = 100

    llm_provider: str = "openai"
    llm_model: str = "gpt-4o-mini"
    llm_api_key: str | None = None
    llm_temperature: float = 0.0
    llm_max_retries: int = 3

    # Hosting / API
    web_host: str = "0.0.0.0"
    web_port: int = 8000

    # Proxy
    proxy_mode: str = "strip"
    proxy_block_threshold: int = 80
    proxy_cache_ttl_seconds: int = 600

    # Live monitor
    monitor_interval_hours: int = 6
    monitor_alert_threshold: int = 40

    # Playwright
    playwright_headless: bool = True
    playwright_timeout_ms: int = 15_000

    # Scoring
    risk_weight_critical: int = 25
    risk_weight_high: int = 10
    risk_weight_medium: int = 3
    risk_weight_low: int = 1

    # Thresholds
    risk_threshold_none: int = 5
    risk_threshold_low: int = 20
    risk_threshold_medium: int = 50
    risk_threshold_high: int = 80
