"""
Path normalisation utilities.

Provides helper functions for normalising URL paths.
"""

from __future__ import annotations

import re
from urllib.parse import unquote


_NUMBER_RE = re.compile(
    r"^\d+$",
)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-"
    r"[0-9a-f]{4}-"
    r"[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}$",
    re.IGNORECASE,
)

_HEX_RE = re.compile(
    r"^[0-9a-f]{16,}$",
    re.IGNORECASE,
)

_TOKEN_RE = re.compile(
    r"^[A-Za-z0-9_-]{20,}$",
)

SERVER_SCRIPT_EXTENSIONS = {
    "php",
    "asp",
    "aspx",
    "jsp",
    "cfm",
    "do",
    "action",
}


def normalise_path(
    path: str,
) -> str:
    """
    Normalises a URL path into a representative endpoint.
    """

    path = unquote(path)

    segments = []

    for segment in path.split("/"):

        if not segment:
            continue

        # Remove HTML entities appended to archived paths.
        if "&" in segment:
            segment = segment.split("&", 1)[0]

        if not segment:
            break

        # Stop at dynamic resource identifiers.
        if _is_dynamic(segment):
            break

        # Collapse implementation files into their endpoint.
        if "." in segment:

            stem, extension = segment.rsplit(".", 1)

            if extension.lower() in SERVER_SCRIPT_EXTENSIONS:

                segment = stem

                # "/index.php" -> "/"
                if segment.lower() == "index":
                    continue

        segments.append(segment)

    if not segments:
        return "/"

    endpoint = "/" + "/".join(segments)

    # Preserve static resources (robots.txt, sitemap.xml, etc.).
    if "." in segments[-1]:
        return endpoint

    return endpoint + "/"


def _is_dynamic(
    segment: str,
) -> bool:
    """
    Returns whether a path segment is likely to identify
    a specific resource instance.
    """

    return (
        _NUMBER_RE.fullmatch(segment)
        or _UUID_RE.fullmatch(segment)
        or _HEX_RE.fullmatch(segment)
        or _TOKEN_RE.fullmatch(segment)
    ) is not None