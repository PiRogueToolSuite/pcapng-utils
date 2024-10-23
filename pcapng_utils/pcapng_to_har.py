#!/usr/bin/env python3
import json
import logging
import platform
from pathlib import Path
from argparse import ArgumentParser
from typing import Any

from pcapng_utils.tshark import Tshark, NetworkTrafficDump
from pcapng_utils.har.pirogue_enrichment import HarEnrichment, Stacktrace, ContentDecryption

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
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

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

    # Arguments for enriching the HAR data
    parser.add_argument(
        "-sf",
        "--socket-operations-file",
        metavar="PATH",
        required=False,
        default=None,
        type=str,
        help="Path to the socket operations data file generated by Pirogue (e.g. socket_trace.json)")
    parser.add_argument(
        "-cf",
        "--cryptography-operations-file",
        metavar="PATH",
        required=False,
        default=None,
        type=str,
        help="Path to the cryptography data file generated by Pirogue (e.g. aes_info.json)")

    args = parser.parse_args()
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s | %(name)s] %(message)s",
        level=logging.DEBUG if args.verbose else logging.WARNING
    )
    try:
        pcapng_to_har(
            args.i,
            args.o,
            tshark=Tshark(args.tshark),
            overwrite=args.force,
            socket_operations_file=args.socket_operations_file,
            cryptography_operations_file=args.cryptography_operations_file
        )
    except Exception as e:
        raise RuntimeError(args.i) from e


def enrich_har_with_io(
    har_data: dict[str, Any],
    enricher: type[HarEnrichment],
    input_dir: Path,
    input_enrichment_file: Path | str | None,
    default_enrichment_file: str,
    logger: logging.Logger,
) -> bool:

    if input_enrichment_file is None:  # use default Pirogue path
        input_enrichment_file = input_dir / default_enrichment_file
        if not input_enrichment_file.is_file():
            return False
    else:
        input_enrichment_file = Path(input_enrichment_file)

    has_been_enriched = enricher(har_data, input_enrichment_file).enrich()
    logger.info(f"The HAR has been enriched with {enricher.ID} data from {input_enrichment_file}")

    return has_been_enriched


def pcapng_to_har(
    input_file: Path | str,
    output_file: Path | str | None = None,
    *,
    tshark: Tshark | None = None,
    socket_operations_file: Path | str | None = None,
    cryptography_operations_file: Path | str | None = None,
    overwrite: bool = False,
    **json_dump_kws: Any,
) -> None:
    """Convert .pcapng file to .har file using tshark"""
    logger = logging.getLogger("pcapng_to_har")
    input_file = Path(input_file)
    if output_file is None:
        output_file = input_file.with_suffix(".har")
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

    # Get the output HAR data (without enrichment)
    har_data = traffic.to_har()

    # Add stacktrace information to the HAR
    enrich_har_with_io(
        har_data,
        Stacktrace,
        input_file.parent,
        socket_operations_file,
        "socket_trace.json",
        logger,
    )

    # Add content decryption to the HAR
    enrich_har_with_io(
        har_data,
        ContentDecryption,
        input_file.parent,
        cryptography_operations_file,
        "aes_info.json",
        logger,
    )

    # Save the enriched HAR data
    json_dump_kws = {'indent': 2, 'ensure_ascii': True, 'allow_nan': False} | json_dump_kws
    with output_file.open("w" if overwrite else "x") as f:
        json.dump(har_data, f, **json_dump_kws)

    logger.info(f"The HAR has been saved in {output_file}")


if __name__ == "__main__":
    cli()
