"""
Source type model.

Defines the supported passive intelligence sources used by Praevia.
"""

from enum import StrEnum


class SourceType(StrEnum):
    """
    Enumerates the passive intelligence sources supported by Praevia.
    """

    CRT_SH = "crt.sh"
    CERTSPOTTER = "CertSpotter"
    WAYBACK = "Wayback Machine"
    WAPPALYZER = "Wappalyzer"
    GITHUB = "GitHub"