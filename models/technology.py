"""
Technology model.

Represents a technology detected during passive reconnaissance.
"""

from dataclasses import dataclass, field

from models.evidence import Evidence
from models.vulnerability import Vulnerability


@dataclass(slots=True)
class Technology:
    """
    Represents a detected technology.
    """

    name: str

    version: str | None = None

    confidence: int = 0

    categories: list[str] = field(
        default_factory=list,
    )

    groups: list[str] = field(
        default_factory=list,
    )

    vulnerabilities: list[Vulnerability] = field(
        default_factory=list,
    )

    evidence: list[Evidence] = field(
        default_factory=list,
    )