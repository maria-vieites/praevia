"""
Evidence model.

Represents supporting information for a discovered entity during
passive reconnaissance.
"""

from dataclasses import dataclass

from models.source_type import SourceType


@dataclass(slots=True)
class Evidence:
    """
    Represents supporting information for a discovered entity.

    An evidence records how a passive intelligence source identified a
    specific finding, providing traceability throughout the
    reconnaissance workflow.
    """

    source: SourceType
    details: str