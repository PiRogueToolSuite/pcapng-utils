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
    try:
        pcapng_to_har(args.i, args.o, tshark=Tshark(args.tshark), overwrite=args.force)
    except Exception as e:
        raise RuntimeError(args.i) from e


def pcapng_to_har(
    input_file: Path | str,
    output_file: Path | str | None = None,
    *,
    tshark: Tshark | None = None,
    overwrite: bool = False,
    **json_dump_kws: Any,
) -> None:
    """Convert .pcapng file to .har file using tshark"""
    input_file = Path(input_file)
    if output_file is None:
        output_file = input_file.with_suffix('.har')
    else:
        output_file = Path(output_file)

    assert output_file != input_file, input_file
    if output_file.exists() and not overwrite:  # fail fast
        raise FileExistsError(output_file)

    if tshark is None:
        tshark = Tshark()  # default executable path

    # Load & parse the traffic from the PCAPNG file
    traffic = NetworkTrafficDump(tshark.load_traffic(input_file))
    traffic.parse_traffic()
    # Save the HAR file
    traffic.save_har(output_file, overwrite=overwrite, **json_dump_kws)


if __name__ == "__main__":
    cli()
