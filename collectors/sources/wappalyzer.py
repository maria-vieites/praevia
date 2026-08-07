"""
Wappalyzer source.

Provides access to Wappalyzer for technology fingerprinting.
"""

from wappalyzer import Wappalyzer

from models.evidence import Evidence
from models.source_type import SourceType
from models.target import Target
from models.technology import Technology


IGNORED_TECHNOLOGY_CATEGORIES = {
    "Font scripts",
    "Miscellaneous",
}


class WappalyzerSource:
    """
    Provides access to Wappalyzer.
    """

    def search(
        self,
        target: Target,
    ) -> list[Technology]:
        """
        Detects technologies used by the target.
        """

        raw = self._scan(
            target,
        )

        return self._parse(
            raw,
        )

    def _scan(
        self,
        target: Target,
    ) -> dict:
        """
        Executes a Wappalyzer scan.
        """

        with Wappalyzer() as scanner:

            return scanner.analyze(
                f"https://{target.host}",
            )

    def _parse(
        self,
        raw: dict,
    ) -> list[Technology]:
        """
        Parses the Wappalyzer output.
        """

        technologies = []

        if not raw:
            return technologies

        # Wappalyzer returns:
        # {
        #     "https://target.com": {
        #         "Technology": {...},
        #         ...
        #     }
        # }

        detected = next(
            iter(raw.values())
        )

        for (
            name,
            details,
        ) in detected.items():

            if self._is_ignored(
                details,
            ):
                continue

            technologies.append(
                self._build_technology(
                    name,
                    details,
                )
            )

        return sorted(
            technologies,
            key=lambda technology: technology.name.lower(),
        )

    def _build_technology(
        self,
        name: str,
        details: dict,
    ) -> Technology:
        """
        Builds a Technology model.
        """

        return Technology(
            name=name,
            version=details.get(
                "version",
            )
            or None,
            confidence=details.get(
                "confidence",
                0,
            ),
            categories=details.get(
                "categories",
                [],
            ),
            groups=details.get(
                "groups",
                [],
            ),
            evidence=[
                Evidence(
                    source=SourceType.WAPPALYZER,
                    details=(
                        "Technology detected "
                        "by Wappalyzer."
                    ),
                )
            ],
        )

    def _is_ignored(
        self,
        details: dict,
    ) -> bool:
        """
        Returns whether the detected technology should be ignored.
        """

        return any(
            category in IGNORED_TECHNOLOGY_CATEGORIES
            for category in details.get(
                "categories",
                [],
            )
        )