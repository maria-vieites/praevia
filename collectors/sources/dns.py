"""
DNS source.

Provides passive DNS resolution for discovered hostnames.
"""

import socket


class DNSSource:
    """
    Provides DNS resolution for hostnames.
    """

    def resolve(
        self,
        hostname: str,
    ) -> list[str]:
        """
        Resolves a hostname to unique IP addresses.

        Both IPv4 and IPv6 addresses are considered.
        """

        addresses: set[str] = set()

        try:
            results = socket.getaddrinfo(
                hostname,
                None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )

        except socket.gaierror:
            return []

        for result in results:
            address = result[4][0]

            if address:
                addresses.add(
                    address,
                )

        return sorted(addresses)