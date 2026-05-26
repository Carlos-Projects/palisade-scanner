from __future__ import annotations

from io import BytesIO
from pathlib import Path

import httpx
from bs4 import BeautifulSoup

from scanner.loaders.base import BaseLoader


class StegoImage:
    """Represents an image loaded for steganographic analysis."""

    def __init__(self, path: str, data: bytes, content_type: str = ""):
        self.path = path
        self.data = data
        self.content_type = content_type
        self._pil_image = None

    @property
    def pil_image(self):
        if self._pil_image is None:
            try:
                from PIL import Image
                self._pil_image = Image.open(BytesIO(self.data))
            except Exception:
                pass
        return self._pil_image

    @property
    def width(self) -> int | None:
        return self.pil_image.width if self.pil_image else None

    @property
    def height(self) -> int | None:
        return self.pil_image.height if self.pil_image else None

    @property
    def mode(self) -> str | None:
        return self.pil_image.mode if self.pil_image else None

    @property
    def format(self) -> str | None:
        return self.pil_image.format if self.pil_image else None

    @property
    def exif(self) -> dict | None:
        if not self.pil_image:
            return None
        try:
            exif_data = self.pil_image.info.get("exif", b"")
            if not exif_data:
                return None
            from PIL import ExifTags
            exif = self.pil_image.getexif()
            return {
                ExifTags.TAGS.get(k, k): str(v)
                for k, v in exif.items()
                if k in ExifTags.TAGS
            }
        except Exception:
            return None

    @property
    def icc(self) -> bytes | None:
        return self.pil_image.info.get("icc_profile") if self.pil_image else None


class ImageLoader(BaseLoader):
    """Loads and parses images from URLs or local paths for stego analysis."""

    def __init__(self, timeout_ms: int = 15_000):
        self.timeout = timeout_ms / 1000

    async def load(self, source: str) -> tuple[str, BeautifulSoup]:
        data, content_type = await self._fetch(source)
        image = StegoImage(source, data, content_type)
        wrapped = self._wrap_in_html(image)
        return source, BeautifulSoup(wrapped, "html.parser")

    async def load_raw(self, source: str) -> StegoImage:
        data, content_type = await self._fetch(source)
        return StegoImage(source, data, content_type)

    async def _fetch(self, source: str) -> tuple[bytes, str]:
        if source.startswith(("http://", "https://")):
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(source)
                resp.raise_for_status()
                return resp.content, resp.headers.get("content-type", "")
        else:
            path = Path(source)
            data = path.read_bytes()
            ext = path.suffix.lower()
            ctype = {
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".gif": "image/gif",
                ".webp": "image/webp",
                ".bmp": "image/bmp",
            }.get(ext, "application/octet-stream")
            return data, ctype

    def _wrap_in_html(self, image: StegoImage) -> str:
        import base64
        b64 = base64.b64encode(image.data).decode()
        return f"""<html><body>
<img src="data:{image.content_type};base64,{b64}" />
<div class="image-meta">
  <span class="img-path">{image.path}</span>
  <span class="img-width">{image.width or ''}</span>
  <span class="img-height">{image.height or ''}</span>
  <span class="img-format">{image.format or ''}</span>
  <span class="img-mode">{image.mode or ''}</span>
</div>
</body></html>"""
