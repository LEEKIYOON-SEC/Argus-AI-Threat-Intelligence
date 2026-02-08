from __future__ import annotations

from dataclasses import dataclass
import io
from pypdf import PdfReader


@dataclass
class PDFExtractResult:
    ok: bool
    text: str
    pages: int
    reason: str


def extract_text_from_pdf_bytes(
    pdf_bytes: bytes,
    *,
    max_pages: int = 8,
    max_chars: int = 7000,
) -> PDFExtractResult:
    if not pdf_bytes:
        return PDFExtractResult(ok=False, text="", pages=0, reason="empty_pdf_bytes")

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
    except Exception as e:
        return PDFExtractResult(ok=False, text="", pages=0, reason=f"pdf_open_failed: {e}")

    total_pages = len(reader.pages)
    n = min(total_pages, max_pages)

    chunks = []
    extracted_any = False

    for i in range(n):
        try:
            page = reader.pages[i]
            t = (page.extract_text() or "").strip()
            if t:
                extracted_any = True
                chunks.append(f"[Page {i+1}]\n{t}\n")
        except Exception:
            continue

    if not extracted_any:
        return PDFExtractResult(
            ok=False,
            text="",
            pages=n,
            reason="no_text_layer_detected_or_extraction_empty (likely scanned PDF; OCR disabled)",
        )

    full = "\n".join(chunks).strip()
    if len(full) > max_chars:
        full = full[:max_chars] + "\n...(truncated)"

    return PDFExtractResult(ok=True, text=full, pages=n, reason="ok")
