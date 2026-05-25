from bs4 import BeautifulSoup

from scanner.loaders.base import BaseLoader


class PDFLoader(BaseLoader):
    """Extracts text from PDF files for scanning."""

    async def load(self, path: str) -> tuple[str, BeautifulSoup]:
        try:
            import fitz  # PyMuPDF
        except ImportError:
            raise ImportError("PDF support requires pymupdf: pip install prompt-injection-scanner[pdf]")

        doc = fitz.open(path)
        html_parts = [f"<html><body><h1>PDF: {path}</h1>"]
        for page_num in range(len(doc)):
            page = doc[page_num]
            text = page.get_text()
            html_parts.append(f'<div class="page" data-page="{page_num + 1}">')
            html_parts.append(f"<pre>{text}</pre>")
            html_parts.append("</div>")
        html_parts.append("</body></html>")
        doc.close()

        html = "\n".join(html_parts)
        soup = BeautifulSoup(html, "lxml")
        return path, soup
