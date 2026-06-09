from __future__ import annotations


def extract_text_from_pdf_bytes(pdf_bytes: bytes) -> str:
    """Extracts text from a PDF byte array using PyMuPDF.

    Returns:
        Extracted text as a string, or an empty string if it fails or is malformed/encrypted.
    """
    try:
        import fitz  # PyMuPDF
    except ImportError:
        return ""

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        if doc.is_encrypted:
            # Try to decrypt with empty password
            if not doc.authenticate(""):
                doc.close()
                return ""

        text_parts = []
        for page in doc:
            text_parts.append(page.get_text())

        doc.close()
        return "\n".join(text_parts)
    except Exception:
        return ""
