"""Atomic JSON report writer."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from iam_analyzer.models import ScanResult

_REPORT_FILE_MODE = 0o600


def write_json_report(scan_result: ScanResult, output_path: str | Path) -> Path:
    """Write a scan result as an atomic, owner-readable JSON report."""
    destination = Path(output_path)
    temporary = destination.with_name(f"{destination.name}.tmp")
    payload = scan_result.model_dump(mode="json")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    file_descriptor = os.open(temporary, flags, _REPORT_FILE_MODE)

    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as report_file:
            file_descriptor = -1
            json.dump(payload, report_file, indent=2, sort_keys=True)
            report_file.write("\n")

        os.replace(temporary, destination)  # noqa: PTH105 - spec requires os.replace.
        destination.chmod(_REPORT_FILE_MODE)
    except BaseException:
        if file_descriptor != -1:
            os.close(file_descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        return destination
