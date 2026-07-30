"""
Base collector interface.

Defines the common contract implemented by all passive reconnaissance
collectors.
"""

from abc import ABC, abstractmethod

from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


class BaseCollector(ABC):
    """
    Defines the common interface for all collectors.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Returns the collector name.
        """

    @abstractmethod
    def collect(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Collects passive reconnaissance information and stores it in the
        shared reconnaissance data model.
        """