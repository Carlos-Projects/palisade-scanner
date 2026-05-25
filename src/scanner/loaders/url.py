from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from scanner.loaders.base import BaseLoader


class URLLoader(BaseLoader):
    """Fetches content from a URL via HTTP."""

    def __init__(self, timeout_ms: int = 30_000):
        self.timeout = timeout_ms / 1000

    async def load(self, url: str) -> tuple[str, BeautifulSoup]:
        if not urlparse(url).scheme:
            url = f"https://{url}"

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={
                "User-Agent": (
                    "PromptInjectionScanner/0.1 "
                    "(security scanner; https://github.com/your-org/prompt-injection-scanner)"
                ),
            },
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            soup = BeautifulSoup(resp.content, "lxml" if "html" in content_type else "html.parser")
            return str(resp.url), soup


class HTMLFileLoader(BaseLoader):
    """Loads from a local HTML file."""

    async def load(self, path: str) -> tuple[str, BeautifulSoup]:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        soup = BeautifulSoup(content, "lxml")
        return path, soup


class PasteLoader(BaseLoader):
    """Loads raw pasted HTML/text."""

    async def load(self, raw: str) -> tuple[str, BeautifulSoup]:
        soup = BeautifulSoup(raw, "lxml")
        return "paste://input", soup
