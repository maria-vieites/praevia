"""
Source type model.

Defines the supported passive intelligence sources used by Praevia.
"""

from enum import StrEnum


class SourceType(StrEnum):
    """
    Enumerates the supported passive intelligence sources.
    """

    CRT_SH = "crt.sh"
    CERTSPOTTER = "CertSpotter"
    DNS = "DNS"
    RDAP = "RDAP"
    WAYBACK = "Wayback Machine"
    WAPPALYZER = "Wappalyzer"
    GITHUB = "GitHub"