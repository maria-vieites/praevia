"""
Historical URL model.

Represents a historical URL identified during passive reconnaissance.
"""

from dataclasses import dataclass, field

from models.evidence import Evidence


@dataclass(slots=True)
class HistoricalURL:
    """
    Represents a historical URL identified during passive reconnaissance.
    """

    url: str
    evidence: list[Evidence] = field(default_factory=list)