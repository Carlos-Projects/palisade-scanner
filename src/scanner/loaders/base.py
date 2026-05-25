from abc import ABC, abstractmethod

from bs4 import BeautifulSoup


class BaseLoader(ABC):
    """Loads content from a source and returns a BeautifulSoup document."""

    @abstractmethod
    async def load(self, source: str) -> tuple[str, BeautifulSoup]:
        """Load content from source, return (url_or_source, soup)."""
        ...
