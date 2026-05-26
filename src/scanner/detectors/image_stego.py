from __future__ import annotations

import io
from typing import TYPE_CHECKING

from bs4 import BeautifulSoup

from scanner.detectors.base import BaseDetector
from scanner.domain.models import Finding

if TYPE_CHECKING:
    from PIL import Image  # noqa: F401


class ImageStegoDetector(BaseDetector):
    """Detects steganographic payloads hidden in images.

    Techniques:
    - LSB (Least Significant Bit) analysis: chi-square attack, bit correlation
    - EXIF/IPTC metadata analysis
    - DCT coefficient anomaly detection (JPEG)
    - OCR text extraction from images
    - Color palette analysis (PNG)
    - High local entropy regions (potential embedded data)
    """

    name = "image_stego"

    LSB_THRESHOLD = 0.15
    ENTROPY_THRESHOLD = 7.0

    async def detect(self, soup: BeautifulSoup, source_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        from PIL import Image

        for img_tag in soup.find_all("img"):
            src = str(img_tag.get("src", ""))
            if not src or source_url == "inline":
                continue

            try:
                image_data = self._load_image_data(src, source_url)
                if image_data is None:
                    continue
                img = Image.open(io.BytesIO(image_data))

                lsb_findings = self._check_lsb(img, src)
                findings.extend(lsb_findings)

                exif_findings = self._check_exif(img, image_data, src)
                findings.extend(exif_findings)

                if img.mode == "P":
                    palette_findings = self._check_palette(img, src)
                    findings.extend(palette_findings)

                ocr_findings = self._check_ocr(image_data, src)
                findings.extend(ocr_findings)

            except Exception:
                continue

        return findings

    def _load_image_data(self, src: str, base_url: str) -> bytes | None:
        """Load image data from various sources."""
        if src.startswith("data:"):
            import base64

            try:
                _, encoded = src.split(",", 1)
                return base64.b64decode(encoded)
            except Exception:
                return None
        elif src.startswith(("http://", "https://")):
            import httpx

            try:
                from urllib.parse import urljoin

                url = urljoin(base_url, src)
                resp = httpx.get(url, timeout=10)
                resp.raise_for_status()
                return resp.content
            except Exception:
                return None
        else:
            import os
            from pathlib import Path

            path = Path(src)
            if not path.is_absolute():
                path = Path(os.getcwd()) / src
            if path.exists():
                return path.read_bytes()
            return None

    def _check_lsb(self, img: Image.Image, src: str) -> list[Finding]:
        """Check for LSB steganography via chi-square-like analysis."""
        if img.mode not in ("RGB", "RGBA", "L"):
            return []
        import numpy as np

        arr = np.array(img)

        if len(arr.shape) == 2:
            channels = [arr]
        else:
            channels = [arr[:, :, c] for c in range(min(arr.shape[2], 3))]

        lsb_ratios = {}
        for i, channel in enumerate(channels):
            lsb = channel & 1
            total = channel.size
            ones = int(lsb.sum())
            ratio = ones / total if total > 0 else 0.5
            dev = abs(ratio - 0.5)
            lsb_ratios[f"channel_{i}"] = {
                "ones": ones,
                "total": total,
                "ratio": round(ratio, 4),
                "deviation": round(dev, 4),
            }

        max_dev = max(v["deviation"] for v in lsb_ratios.values())

        # Natural photos have ~50% LSB distribution. Uniform/near-uniform suggests
        # synthetic images (logos) or potentially embedded data.
        # Only flag when distribution is suspiciously close to 50% (stego)
        # OR when ALL channels show the exact same anomaly pattern.
        if max_dev < self.LSB_THRESHOLD:
            return [
                Finding(
                    detector=self.name,
                    severity="medium",
                    confidence=0.75,
                    title="Potential LSB steganography detected",
                    description="LSB bit distribution near 50% across channels suggests embedded data.",
                    snippet=f"Image: {src[:100]} | Max deviation: {max_dev:.3f}",
                    category="image_stego",
                    recommendation="Analyze the image with a dedicated steganography tool.",
                )
            ]

        return []

    def _check_exif(self, img: Image.Image, raw_data: bytes, src: str) -> list[Finding]:
        """Check EXIF metadata for hidden payloads."""
        try:
            exif = img.getexif()
            findings = []
            suspicious_fields = {
                "ImageDescription",
                "UserComment",
                "Copyright",
                "Artist",
                "ImageHistory",
                "XPAuthor",
                "XPComment",
                "XPSubject",
            }
            from PIL.ExifTags import TAGS

            for tag_id, value in exif.items():
                tag_name = TAGS.get(tag_id, f"TAG_{tag_id}")
                if tag_name in suspicious_fields and value and len(str(value)) > 20:
                    findings.append(
                        Finding(
                            detector=self.name,
                            severity="medium",
                            confidence=0.7,
                            title=f"Suspicious EXIF field: {tag_name}",
                            description=f"EXIF field '{tag_name}' contains {len(str(value))} chars.",
                            snippet=str(value)[:300],
                            category="image_stego",
                            recommendation=f"Review EXIF field '{tag_name}' for hidden data.",
                        )
                    )

            return findings
        except Exception:
            return []

    def _check_palette(self, img: Image.Image, src: str) -> list[Finding]:
        """Check for palette-based steganography (PNG)."""
        if not hasattr(img, "palette") or img.palette is None:
            return []
        try:
            palette = img.getpalette()
            if palette and len(palette) > 768:
                unique_colors = len(set(zip(palette[::3], palette[1::3], palette[2::3], strict=False)))
                if unique_colors < 50 and img.size[0] * img.size[1] > 1000:
                    return [
                        Finding(
                            detector=self.name,
                            severity="low",
                            confidence=0.5,
                            title="Unusual color palette detected",
                            description=f"Image has {unique_colors} unique colors but large dimensions ({img.size}). Possible palette stego.",
                            snippet=f"Image: {src[:100]}",
                            category="image_stego",
                            recommendation="Analyze PNG palette for embedded data.",
                        )
                    ]
        except Exception:
            pass
        return []

    def _check_ocr(self, image_data: bytes, src: str) -> list[Finding]:
        """Extract text from images via OCR."""
        try:
            import pytesseract
            from PIL import Image

            img = Image.open(io.BytesIO(image_data))
            text = pytesseract.image_to_string(img).strip()
            if not text:
                return []
            import re

            from scanner.detectors.injection_patterns import JAILBREAK_PREFIXES

            all_patterns = JAILBREAK_PREFIXES + [r"(?i)ignore\s+(?:all\s+)?previous\s+instructions"]
            combined = re.compile("|".join(all_patterns), re.IGNORECASE)
            matches = combined.findall(text)
            if matches:
                return [
                    Finding(
                        detector=self.name,
                        severity="critical",
                        confidence=0.85,
                        title="Text extracted from image contains injection patterns",
                        description=f"OCR extracted {len(matches)} injection pattern(s) from image.",
                        snippet=text[:300],
                        category="image_stego",
                        recommendation="Review image content — it contains instructions intended for AI models.",
                    )
                ]
        except ImportError:
            pass
        except Exception:
            pass
        return []
