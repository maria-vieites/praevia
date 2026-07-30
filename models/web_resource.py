"""
Web resource model.

Represents a web resource identified during passive reconnaissance.
"""

from dataclasses import dataclass, field

from models.evidence import Evidence


@dataclass(slots=True)
class WebResource:
    """
    Represents a web resource identified during passive reconnaissance.
    """

    url: str
    evidence: list[Evidence] = field(default_factory=list)