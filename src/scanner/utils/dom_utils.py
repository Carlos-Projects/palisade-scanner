from bs4 import BeautifulSoup, Tag

from scanner.domain.models import TextNode


def find_text_nodes(soup: BeautifulSoup) -> list[TextNode]:
    """Extract all text nodes from the DOM with position metadata."""
    nodes = []

    for el in soup.find_all(True):
        if not isinstance(el, Tag):
            continue

        text = el.get_text(strip=True)
        if not text:
            continue

        style = str(el.get("style", "") or "").lower()
        tag = el.name or ""

        is_hidden, method = _detect_hidden(style, el)
        selector = _make_selector(el)

        nodes.append(
            TextNode(
                content=text[:500],
                selector=selector,
                tag=tag,
                visible=not is_hidden,
                is_hidden=is_hidden,
                hidden_method=method or None,
                font_size=_extract_font_size(style),
                opacity=_extract_opacity(style) or 0.0,
            )
        )

    return nodes


def get_visible_text(soup: BeautifulSoup) -> str:
    """Get only visible text from the DOM."""
    parts = []
    for el in soup.find_all(True):
        if not isinstance(el, Tag):
            continue
        if not _is_visible(el):
            continue
        text = el.get_text(strip=True)
        if text:
            parts.append(text)
    return "\n".join(parts)


def _is_visible(el: Tag) -> bool:
    style = str(el.get("style", "") or "").lower()
    hidden, _ = _detect_hidden(style, el)
    return not hidden


def _detect_hidden(style: str, el: Tag | None = None) -> tuple[bool, str | None]:
    if "display:none" in style or "display: none" in style:
        return True, "display:none"
    if "visibility:hidden" in style or "visibility: hidden" in style:
        return True, "visibility:hidden"
    if "opacity:0" in style or "opacity: 0" in style:
        return True, "opacity:0"
    if el and (el.get("aria-hidden") == "true" or el.get("hidden") is not None):
        return True, "attribute"
    return False, None


def _make_selector(el: Tag) -> str:
    parts = []
    if el.get("id"):
        return f"#{el['id']}"
    if el.name:
        parts.append(el.name)
    if el.get("class"):
        parts.append("." + ".".join(el["class"]))
    return "".join(parts) if parts else el.name or "unknown"


def _extract_font_size(style: str) -> int | None:
    import re

    m = re.search(r"font-size\s*:\s*(\d+)", style)
    if m:
        return int(m.group(1))
    return None


def _extract_opacity(style: str) -> float | None:
    import re

    m = re.search(r"opacity\s*:\s*([\d.]+)", style)
    if m:
        return float(m.group(1))
    return None
