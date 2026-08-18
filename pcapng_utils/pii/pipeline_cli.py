"""CLI for the complete PCAPNG-to-PII-report pipeline."""

from __future__ import annotations

import argparse
from pathlib import Path

from .cli import print_summary, write_report
from .pipeline import scan_pcapng


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert PCAPNG traffic and produce a masked PII JSON report."
    )
    parser.add_argument("-i", "--input", required=True, type=Path, help="Input PCAPNG file")
    parser.add_argument("-o", "--output", type=Path, help="Output PII report path")
    parser.add_argument(
        "-c",
        "--tshark",
        default="tshark",
        help="TShark command or executable path",
    )
    parser.add_argument(
        "--har-output",
        type=Path,
        help="Keep the intermediate HAR at this path (temporary by default)",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite existing report and retained HAR outputs",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    input_path: Path = args.input
    output_path: Path = args.output or input_path.with_suffix(".pii.json")

    if not input_path.is_file():
        parser.error(f"Input PCAPNG does not exist: {input_path}")
    if output_path.exists() and not args.force:
        parser.error(f"Output report already exists: {output_path} (use --force to overwrite)")
    if args.har_output is not None and args.har_output.exists() and not args.force:
        parser.error(
            f"Intermediate HAR already exists: {args.har_output} (use --force to overwrite)"
        )

    report = scan_pcapng(
        input_path,
        tshark_command=args.tshark,
        har_output=args.har_output,
        overwrite=args.force,
    )
    write_report(report, output_path, overwrite=args.force)
    print_summary(report, output_path)
    if args.har_output is None:
        print("Intermediate HAR: removed after scanning")
    else:
        print(f"Intermediate HAR: {args.har_output}")


if __name__ == "__main__":
    main()
