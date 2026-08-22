"""Report generation for logscan.

Writes analysis results to CSV or JSON files, guarding against CSV
injection by sanitizing field values.
"""

from __future__ import annotations

import csv
import json
import os
from typing import Any, Dict, List, Sequence

from .config import SUPPORTED_FORMATS

# CSV-injection-prone leading characters.
_CSV_HAZARD_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\u0000")


class ReportGeneratorError(Exception):
    """Base exception for report generation errors."""


def _sanitize(value: Any) -> Any:
    """Neutralize CSV injection for string values.

    Values beginning with characters that spreadsheets interpret as
    formulas are prefixed with a single quote to neutralize them.
    """
    if isinstance(value, str):
        if value and value[0] in _CSV_HAZARD_PREFIXES:
            return "'" + value
        return value
    return value


def _normalize_results(results: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return a normalized list of records with required keys."""
    normalized: List[Dict[str, Any]] = []
    for record in results:
        item = {
            "artefact": record.get("artefact", ""),
            "result": record.get("result", ""),
            "date": record.get("date", ""),
        }
        normalized.append(item)
    return normalized


def generate_csv(results: Sequence[Dict[str, Any]], output_path: str) -> str:
    """Write results to a CSV file with a header row.

    Returns the absolute output path.
    """
    rows = _normalize_results(results)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    try:
        with open(output_path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["artefact", "result", "date"])
            for row in rows:
                writer.writerow(
                    [
                        _sanitize(row["artefact"]),
                        _sanitize(row["result"]),
                        _sanitize(row["date"]),
                    ]
                )
    except OSError as exc:
        raise ReportGeneratorError(f"Failed to write CSV report: {exc}") from exc
    return os.path.abspath(output_path)


def generate_json(results: Sequence[Dict[str, Any]], output_path: str) -> str:
    """Write results to a JSON file (a list of records).

    Returns the absolute output path.
    """
    rows = _normalize_results(results)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2, ensure_ascii=False)
    except OSError as exc:
        raise ReportGeneratorError(f"Failed to write JSON report: {exc}") from exc
    return os.path.abspath(output_path)


def generate(results: Sequence[Dict[str, Any]], fmt: str, output_path: str) -> str:
    """Dispatch to the appropriate generator based on ``fmt``.

    Args:
        results: Sequence of records with ``artefact``, ``result``, ``date``.
        fmt: Report format; one of the ``SUPPORTED_FORMATS``.
        output_path: Destination file path.

    Returns:
        The absolute path of the generated report.

    Raises:
        ReportGeneratorError: If ``fmt`` is unsupported or writing fails.
    """
    fmt = str(fmt).strip().lower()
    if fmt not in SUPPORTED_FORMATS:
        raise ReportGeneratorError(
            f"Unsupported report format: {fmt!r}. "
            f"Supported: {', '.join(SUPPORTED_FORMATS)}"
        )
    if fmt == "json":
        return generate_json(results, output_path)
    return generate_csv(results, output_path)
