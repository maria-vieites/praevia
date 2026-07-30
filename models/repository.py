"""
Repository model.

Represents a public repository identified during passive reconnaissance.
"""

from dataclasses import dataclass, field

from models.evidence import Evidence


@dataclass(slots=True)
class Repository:
    """
    Represents a public repository identified during passive reconnaissance.
    """

    platform: str
    owner: str
    name: str
    url: str
    evidence: list[Evidence] = field(default_factory=list)