"""Command-line interface for HAR PII scanning."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .har_scanner import HarPiiScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a HAR file for common Chinese PII and write a masked JSON report."
    )
    parser.add_argument("-i", "--input", required=True, type=Path, help="Input HAR file")
    parser.add_argument("-o", "--output", type=Path, help="Output report path")
    parser.add_argument("-f", "--force", action="store_true", help="Overwrite an existing report")
    return parser


def write_report(report: dict, output_path: Path, *, overwrite: bool = False) -> None:
    """Write a report without silently replacing an existing file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w" if overwrite else "x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def print_summary(report: dict, output_path: Path) -> None:
    """Print the occurrence and unique-value totals for a completed scan."""
    summary = report["summary"]
    print(
        f"Scanned {summary['total_entries']} HAR entries; "
        f"found {summary['finding_count']} PII occurrence(s), "
        f"representing {summary['unique_finding_count']} unique value(s), in "
        f"{summary['entries_with_pii']} entry/entries."
    )
    print(f"Masked report: {output_path}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    input_path: Path = args.input
    output_path: Path = args.output or input_path.with_suffix(".pii.json")

    if not input_path.is_file():
        parser.error(f"Input HAR does not exist: {input_path}")
    if output_path.exists() and not args.force:
        parser.error(f"Output report already exists: {output_path} (use --force to overwrite)")

    report = HarPiiScanner().scan_file(input_path)
    write_report(report, output_path, overwrite=args.force)
    print_summary(report, output_path)


if __name__ == "__main__":
    main()
