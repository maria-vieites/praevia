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
DEFAULT_TIMEOUT = 30

DEBUG = True