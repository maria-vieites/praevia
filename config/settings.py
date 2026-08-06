"""
Application settings for Praevia.
"""

VERSION = "0.1.0"

SUPPORTED_OUTPUTS = (
    "html",
    "json",
    "pdf",
)

DEFAULT_OUTPUT = [
    "html",
]

DEFAULT_OUTPUT_DIRECTORY = "reports"


HTTP_TIMEOUT = 20
WAYBACK_TIMEOUT = 90

DEBUG = True

# Optional API keys.
CERTSPOTTER_API_KEY = None