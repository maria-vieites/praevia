"""
IP address model.

Represents an IP address associated with a discovered hostname,
together with publicly observable network information.
"""

from dataclasses import dataclass, field

from models.evidence import Evidence


@dataclass(slots=True)
class IPAddress:
    """
    Represents an IP address and its network context.
    """

    address: str

    organization: str | None = None

    network: str | None = None

    evidence: list[Evidence] = field(
        default_factory=list,
    )