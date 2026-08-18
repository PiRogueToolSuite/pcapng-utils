"""One-command PCAPNG-to-masked-PII-report pipeline."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from pcapng_utils.pcapng_to_har import pcapng_to_har
from pcapng_utils.tshark import Tshark

from .har_scanner import HarPiiScanner


def scan_pcapng(
    input_path: Path,
    *,
    tshark_command: str = "tshark",
    har_output: Path | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Convert PCAPNG to HAR and return a masked PII report.

    When ``har_output`` is omitted, the intermediate HAR is created in a
    temporary directory and deleted immediately after scanning.
    """
    tshark = Tshark(tshark_cmd=tshark_command)

    if har_output is not None:
        pcapng_to_har(input_path, har_output, tshark=tshark, overwrite=overwrite)
        return HarPiiScanner().scan_file(
            har_output,
            source_name=input_path.name,
            source_format="pcapng",
        )

    with TemporaryDirectory(prefix="netpii-") as temporary_directory:
        temporary_har = Path(temporary_directory) / "intermediate.har"
        pcapng_to_har(input_path, temporary_har, tshark=tshark)
        return HarPiiScanner().scan_file(
            temporary_har,
            source_name=input_path.name,
            source_format="pcapng",
        )
