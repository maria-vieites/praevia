"""
Technology model.

Represents a technology identified during passive reconnaissance.
"""

from dataclasses import dataclass, field

from models.evidence import Evidence


@dataclass(slots=True)
class Technology:
    """
    Represents a technology identified during passive reconnaissance.
    """

    name: str
    version: str | None = None
    evidence: list[Evidence] = field(default_factory=list)