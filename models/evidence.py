"""
Evidence model.

Represents supporting information for a discovered entity during
passive reconnaissance.
"""

from dataclasses import dataclass


@dataclass(slots=True)
class Evidence:
    """
    Represents supporting information for a discovered entity.

    An evidence records how a collector identified a specific finding,
    providing traceability throughout the reconnaissance workflow.
    """

    collector: str
    details: str