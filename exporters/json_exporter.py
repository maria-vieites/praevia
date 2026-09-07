"""
JSON exporter for complete Praevia reconnaissance data.
"""

import json
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from config.settings import VERSION
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


def _to_serializable(
    value: Any,
) -> Any:
    """
    Convert Praevia model objects into JSON-compatible values.
    """

    if isinstance(
        value,
        Enum,
    ):

        return value.value

    if is_dataclass(
        value,
    ):

        return {
            field.name: _to_serializable(
                getattr(
                    value,
                    field.name,
                )
            )
            for field in fields(
                value,
            )
        }

    if isinstance(
        value,
        dict,
    ):

        return {
            str(key): _to_serializable(
                item,
            )
            for key, item in value.items()
        }

    if isinstance(
        value,
        (list, tuple, set),
    ):

        return [
            _to_serializable(
                item,
            )
            for item in value
        ]

    return value


def build_document(
    target: Target,
    data: ReconnaissanceData,
) -> dict[str, Any]:
    """
    Build the complete JSON document for a Praevia execution.
    """

    return {
        "praevia": {
            "version": VERSION,
            "target": _to_serializable(
                target,
            ),
        },
        "reconnaissance": _to_serializable(
            data,
        ),
    }


def export_json(
    target: Target,
    data: ReconnaissanceData,
    output_directory: str,
) -> Path:
    """
    Export complete reconnaissance data to a JSON file.
    """

    directory = Path(
        output_directory,
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = directory / "praevia.json"

    document = build_document(
        target,
        data,
    )

    output_path.write_text(
        json.dumps(
            document,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return output_path