"""
Application settings for Praevia.
"""

import os


VERSION = "0.1.0"

SUPPORTED_OUTPUTS = (
    "json",
)

DEFAULT_OUTPUT_DIRECTORY = "reports"


HIGH_PRIORITY_STYLE = "bold red"
MEDIUM_PRIORITY_STYLE = "bold dark_orange"
LOW_PRIORITY_STYLE = "bold yellow"
INFO_PRIORITY_STYLE = "bold grey70"


HTTP_TIMEOUT = 20
WAYBACK_TIMEOUT = 90


# Optional API keys.
CERTSPOTTER_API_KEY = os.getenv(
    "CERTSPOTTER_API_KEY",
)