#!/usr/bin/env python3

import platform
from pathlib import Path
from argparse import ArgumentParser
from typing import Any

from pcapng_utils.tshark.traffic import NetworkTrafficDump
from pcapng_utils.tshark.wrapper import Tshark

DEFAULT_TSHARK_PATH = {
    "Linux": "/usr/bin/tshark",
    "Darwin": "/Applications/Wireshark.app/Contents/MacOS/tshark",
}.get(platform.system())


def cli() -> None:
    """CLI script for converting .pcapng file to .har file using tshark"""
    parser = ArgumentParser("Convert PCAPng -> HAR")
    parser.add_argument("-i", metavar="PATH", type=str, required=True, help="Path to input .pcapng")
    parser.add_argument("-o", metavar="PATH", type=str, default=None, help="Path to output .har")
    parser.add_argument("-f", "--force", action="store_true", help="Whether to overwrite output if it exists")

    if DEFAULT_TSHARK_PATH and Path(DEFAULT_TSHARK_PATH).exists():
        parser.add_argument(
            "--tshark",
            type=str,
            default=DEFAULT_TSHARK_PATH,
            help=f"Path to tshark executable (default: {DEFAULT_TSHARK_PATH})",
        )
    else:
        parser.add_argument(
            "--tshark",
            type=str,
            required=True,
            help="Path to tshark executable",
        )

    args = parser.parse_args()
    input_file = Path(args.i)
    output_file = Path(args.o) if args.o else input_file.with_suffix(".har")
    try:
        pcapng_to_har(input_file, output_file, tshark_path=args.tshark, overwrite=args.force)
    except Exception as e:
        raise RuntimeError(input_file) from e


def pcapng_to_har(
    input_file: Path, output_file: Path, *, tshark_path: Path, overwrite: bool = False, **json_dump_kws: Any
) -> None:
    """Convert .pcapng file to .har file using tshark"""
    assert output_file != input_file
    if output_file.exists() and not overwrite:  # fail fast
        raise FileExistsError(output_file)

    # Load the traffic from the PCAPNG file
    tshark_wrapper = Tshark(pcapng_file=input_file, tshark_path=str(tshark_path))
    tshark_wrapper.load_traffic()
    # Parse the traffic
    assert isinstance(tshark_wrapper.traffic, list)
    traffic = NetworkTrafficDump(tshark_wrapper.traffic)
    traffic.parse_traffic()
    # Save the HAR file
    traffic.save_har(output_file, overwrite=overwrite, **json_dump_kws)


if __name__ == "__main__":
    cli()
