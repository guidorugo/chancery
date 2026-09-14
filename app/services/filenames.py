"""Content-Disposition helpers (assessment G8-1).

gunicorn writes HTTP/1.x response headers as latin-1, so a filename containing
any character outside ISO-8859-1 (Polish, Cyrillic, Greek, CJK, ...) raised a
UnicodeEncodeError while the headers were being written and the download
failed with a 500 — including the public CRL and CA-certificate endpoints
relying parties depend on. The Flask test client never goes through that
path, which is why the suite could not catch it.

The `filename=` parameter is therefore restricted to ASCII, and when that
loses information the original name travels in the RFC 5987 `filename*`
parameter (percent-encoded UTF-8), which browsers prefer when present.
"""
import re
from urllib.parse import quote

_ASCII_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def ascii_filename(name, fallback="download"):
    """ASCII-only, header-safe form of `name`.

    Returns `fallback` when the name is mostly lost in translation (fewer than
    half of its characters are header-safe, e.g. "Łódź" → "__d_"), so a
    non-Latin name yields "ca-7.crl" rather than a row of underscores.
    """
    name = name or ""
    safe = _ASCII_UNSAFE.sub("_", name)
    kept = sum(1 for a, b in zip(name, safe) if a == b)
    if not safe.strip("._-") or kept * 2 < len(name):
        return fallback
    return safe


def content_disposition(name, extension, fallback="download"):
    """`attachment` Content-Disposition value for `<name>.<extension>`.

    The value is pure ASCII: quotes, semicolons, newlines and non-ASCII
    characters can never reach the header. When the ASCII form differs from
    the original name, `filename*=UTF-8''...` carries the exact name.
    """
    ascii_name = ascii_filename(name, fallback)
    value = f'attachment; filename="{ascii_name}.{extension}"'
    if ascii_name != (name or ""):
        utf8_name = f"{name}.{extension}" if name else f"{fallback}.{extension}"
        value += f"; filename*=UTF-8''{quote(utf8_name, safe='')}"
    return value
