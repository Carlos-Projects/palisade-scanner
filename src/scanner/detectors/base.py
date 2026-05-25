from __future__ import annotations

from abc import ABC, abstractmethod

from bs4 import BeautifulSoup

from scanner.domain.models import Finding


class BaseDetector(ABC):
    """Abstract base for all detectors."""

    name: str = "base"

    @abstractmethod
    async def detect(self, soup: BeautifulSoup, source_url: str = "") -> list[Finding]:
        ...
