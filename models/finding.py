"""
Finding model.

Represents prioritised investigation recommendations generated from passive
reconnaissance data.
"""

from dataclasses import dataclass

from models.investigation_priority import InvestigationPriority


@dataclass(slots=True)
class Finding:
    """
    Represents a prioritised investigation recommendation.
    """

    title: str
    description: str
    priority: InvestigationPriority
    recommendation: str