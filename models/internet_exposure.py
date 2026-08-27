"""
Internet exposure model.

Represents publicly observable information about an IP address
reported by an external passive intelligence source.
"""

from dataclasses import dataclass, field

from models.evidence import Evidence


@dataclass(slots=True)
class InternetExposure:
    """
    Represents public exposure information observed for an IP address.

    The values stored here are observations about the IP address. They
    are not, by themselves, assertions that the observed services or
    vulnerabilities belong to a specific hostname or target.
    """

    ip_address: str

    ports: list[int] = field(
        default_factory=list,
    )

    cpes: list[str] = field(
        default_factory=list,
    )

    hostnames: list[str] = field(
        default_factory=list,
    )

    tags: list[str] = field(
        default_factory=list,
    )

    vulnerabilities: list[str] = field(
        default_factory=list,
    )

    evidence: list[Evidence] = field(
        default_factory=list,
    )