import ipaddress
import socket
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from scanner.loaders.base import BaseLoader


def _validate_url(url: str) -> str:
    """Validate URL scheme and block private IPs (SSRF protection)."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
        parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL scheme '{parsed.scheme}' not allowed")
    if not parsed.hostname:
        raise ValueError("URL must have a hostname")
    try:
        addrs = socket.getaddrinfo(parsed.hostname, None)
        for family, _, _, _, sockaddr in addrs:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                raise ValueError(f"URL resolves to private IP: {sockaddr[0]}")
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {parsed.hostname}")
    return url


class URLLoader(BaseLoader):
    """Fetches content from a URL via HTTP."""

    def __init__(self, timeout_ms: int = 30_000, max_redirects: int = 5):
        self.timeout = timeout_ms / 1000
        self.max_redirects = max_redirects

    async def load(self, url: str) -> tuple[str, BeautifulSoup]:
        url = _validate_url(url)

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            headers={
                "User-Agent": (
                    "PromptInjectionScanner/0.1 "
                    "(security scanner; https://github.com/your-org/prompt-injection-scanner)"
                ),
            },
        ) as client:
            resp = await client.get(url)
            redirect_count = 0
            while resp.is_redirect and redirect_count < self.max_redirects:
                redirect_url = resp.headers.get("location", "")
                if not redirect_url:
                    break
                redirect_url = _validate_url(redirect_url)
                resp = await client.get(redirect_url)
                redirect_count += 1
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            soup = BeautifulSoup(resp.content, "lxml" if "html" in content_type else "html.parser")
            return str(resp.url), soup


class HTMLFileLoader(BaseLoader):
    """Loads from a local HTML file."""

    async def load(self, path: str) -> tuple[str, BeautifulSoup]:
        with open(path, encoding="utf-8") as f:
            content = f.read()
        soup = BeautifulSoup(content, "lxml")
        return path, soup


class PasteLoader(BaseLoader):
    """Loads raw pasted HTML/text."""

    async def load(self, raw: str) -> tuple[str, BeautifulSoup]:
        soup = BeautifulSoup(raw, "lxml")
        return "paste://input", soup
