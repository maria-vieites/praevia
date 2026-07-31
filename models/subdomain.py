"""
Subdomain model.

Represents a subdomain identified during passive reconnaissance.
"""

from dataclasses import dataclass, field

from models.evidence import Evidence


@dataclass(slots=True)
class Subdomain:
    """
    Represents a subdomain identified during passive reconnaissance.
    """

    hostname: str
    evidence: list[Evidence] = field(default_factory=list)