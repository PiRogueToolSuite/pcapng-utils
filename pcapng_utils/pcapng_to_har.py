#!/usr/bin/env python3
import json
import logging
import platform
from dataclasses import dataclass, field, KW_ONLY
from pathlib import Path
from typing import Any, Annotated, Literal, get_args

import tyro

from pcapng_utils.tshark import Tshark, NetworkTrafficDump
from pcapng_utils.har.pirogue_enrichment import HarEnrichment, Stacktrace, ContentDecryption

DEFAULT_TSHARK_PATH = {
    "Linux": "/usr/bin/tshark",
    "Darwin": "/Applications/Wireshark.app/Contents/MacOS/tshark",
}.get(platform.system())

TrueValueType = Literal[1, "1", True, "true", "True", "TRUE"]


@dataclass(frozen=True)
class PcapngToHar:
    """CLI script for converting .pcapng file to .har file using tshark"""

    input: Annotated[Path, tyro.conf.arg(aliases=("-i",))]
    """Path to input .pcapng"""

    output: Annotated[Path | None, tyro.conf.arg(aliases=("-o",), metavar="PATH")] = None
    """Path to output .har (if unset: INPUT.har)"""

    _: KW_ONLY

    tshark_out: Annotated[TrueValueType | str | None, tyro.conf.arg(aliases=("-ot",), metavar="PATH|1")] = None
    """Path to raw tshark output as .json (optional, if `ot=1` -> OUTPUT.json)"""

    # Arguments for enriching the HAR data

    time_shift: Annotated[float, tyro.conf.arg(metavar="SECONDS")] = 0.0
    """
    Systematic time shift in seconds between socket operations timestamps vs. network traffic timestamps.
    Positive means network traffic timestamps (Pirogue date) were earlier than socket operations timestamps (phone date).
    """

    socket_operations_file: Annotated[Path | None, tyro.conf.arg(aliases=("-sf",), metavar="PATH")] = None
    """Path to the socket operations data file generated by Pirogue (if unset: INPUT_DIR/socket_trace.json)"""

    cryptography_operations_file: Annotated[Path | None, tyro.conf.arg(aliases=("-cf",), metavar="PATH")] = None
    """Path to the cryptography data file generated by Pirogue (if unset: INPUT_DIR/aes_info.json)"""

    tshark: str = (
        field(default=DEFAULT_TSHARK_PATH) if DEFAULT_TSHARK_PATH and Path(DEFAULT_TSHARK_PATH).exists() else field()
    )
    """Path/command for tshark executable"""

    force: Annotated[bool, tyro.conf.arg(aliases=("-f",))] = False
    """Whether to overwrite output if it exists"""

    verbose: Annotated[bool, tyro.conf.arg(aliases=("-v",))] = False
    """Activate verbose logging"""

    @classmethod
    def cli(cls) -> None:
        cfg = tyro.cli(cls, config=(tyro.conf.FlagCreatePairsOff,))
        logging.basicConfig(
            format="%(asctime)s [%(levelname)s | %(name)s] %(message)s",
            level=logging.DEBUG if cfg.verbose else logging.WARNING,
        )
        cfg.run()

    @property
    def output_raw_tshark(self) -> Path | Literal[True] | None:
        if self.tshark_out is None:
            return None
        if self.tshark_out in get_args(TrueValueType):
            return True
        assert self.tshark_out
        return Path(self.tshark_out)  # type: ignore

    def run(self, **json_dump_kws: Any) -> None:
        try:
            pcapng_to_har(
                self.input,
                self.output,
                tshark=Tshark(self.tshark),
                output_raw_tshark=self.output_raw_tshark,
                socket_operations_file=self.socket_operations_file,
                cryptography_operations_file=self.cryptography_operations_file,
                overwrite=self.force,
                systematic_time_shift=self.time_shift,
                **json_dump_kws,
            )
        except Exception as e:
            raise RuntimeError(self.input.resolve()) from e


def pcapng_to_har(
    input_file: Path,
    output_file: Path | None = None,
    *,
    tshark: Tshark | None = None,
    output_raw_tshark: Path | Literal[True] | None = None,
    socket_operations_file: Path | None = None,
    cryptography_operations_file: Path | None = None,
    overwrite: bool = False,
    systematic_time_shift: float = 0.0, # for stacktrace enrichment only
    **json_dump_kws: Any,
) -> None:
    """Convert .pcapng file to .har file using tshark"""
    logger = logging.getLogger("pcapng_to_har")
    if output_file is None:
        output_file = input_file.with_suffix(".har")

    if output_raw_tshark is True:
        output_raw_tshark = output_file.with_suffix(".json")

    assert len({input_file, output_file, output_raw_tshark}) == 3, input_file.resolve()
    if not overwrite:  # fail fast
        if output_raw_tshark is not None and output_raw_tshark.exists():
            raise FileExistsError(output_raw_tshark)
        if output_file.exists():
            raise FileExistsError(output_file)

    if tshark is None:
        tshark = Tshark()  # default executable path

    # Load & parse the traffic from the PCAPNG file
    tshark_out = tshark.load_traffic(input_file)
    logger.debug(f"Successfully run tshark: metadata={tshark_out.metadata}")
    if output_raw_tshark:
        with output_raw_tshark.open("w" if overwrite else "x") as fp:
            json.dump(tshark_out.list_packets, fp, indent=2, ensure_ascii=False)
        logger.info(f"Successfully wrote tshark raw output in {output_raw_tshark}")

    traffic = NetworkTrafficDump(tshark_out)
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
        systematic_time_shift=systematic_time_shift,
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
    json_dump_kws = {"indent": 2, "ensure_ascii": True, "allow_nan": False} | json_dump_kws
    with output_file.open("w" if overwrite else "x") as f:
        json.dump(har_data, f, **json_dump_kws)

    logger.info(f"The HAR has been saved in {output_file}")


def enrich_har_with_io(
    har_data: dict[str, Any],
    enricher: type[HarEnrichment],
    input_dir: Path,
    input_enrichment_file: Path | str | None,
    default_enrichment_file: str,
    logger: logging.Logger,
    **enrich_params: Any,
) -> bool:

    if input_enrichment_file is None:  # use default Pirogue path
        input_enrichment_file = input_dir / default_enrichment_file
        if not input_enrichment_file.is_file():
            return False
    else:
        input_enrichment_file = Path(input_enrichment_file)

    has_been_enriched = enricher(har_data, input_enrichment_file, **enrich_params).enrich()
    logger.info(f"The HAR has been enriched with {enricher.ID} data from {input_enrichment_file}")

    return has_been_enriched


if __name__ == "__main__":
    PcapngToHar.cli()
