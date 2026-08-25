"""
Subdomain model.

Represents a hostname identified during passive reconnaissance.
"""

from dataclasses import dataclass, field

from models.evidence import Evidence
from models.ip_address import IPAddress


@dataclass(slots=True)
class Subdomain:
    """
    Represents a hostname identified during passive reconnaissance.
    """

    hostname: str

    ip_addresses: list[IPAddress] = field(
        default_factory=list,
    )

    evidence: list[Evidence] = field(
        default_factory=list,
    )

    def add_ip_address(
        self,
        ip_address: str,
    ) -> IPAddress:
        """
        Adds an IP address if it is not already associated
        with the hostname.

        Returns:
            The existing or newly created IPAddress object.
        """

        for existing in self.ip_addresses:

            if existing.address == ip_address:
                return existing

        ip = IPAddress(
            address=ip_address,
        )

        self.ip_addresses.append(
            ip,
        )

        return ip