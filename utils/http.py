"""
HTTP utilities.

Provides helper functions for performing HTTP requests.
"""

import requests

from config.settings import HTTP_TIMEOUT


def get_json(
    url: str,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> list | dict:
    """
    Performs an HTTP GET request and returns the JSON response.

    Args:
        url: URL to request.
        params: Optional query string parameters.
        headers: Optional HTTP headers.

    Returns:
        The decoded JSON response.

    Raises:
        requests.RequestException: If the request fails.
    """

    response = requests.get(
        url,
        params=params,
        headers=headers,
        timeout=HTTP_TIMEOUT,
    )

    response.raise_for_status()

    return response.json()