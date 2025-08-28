from operator import itemgetter
from datetime import datetime, timezone
from typing import Any

from pcapng_utils import __version__
from .types import ParsedTrafficProtocol
from .wrapper import TsharkOutput


class NetworkTrafficDump:
    """
    The NetworkTrafficDump class is designed to handle and process network traffic data.

    Attributes:
        creation_metadata (dict): Some metadata of input file to export in HAR creator comment
        traffic (list[dict]): A list of dictionaries containing traffic data.
        parsed_traffic (dict[class, instance]): Mapping of parsed traffic per protocol class
            (e.g. Http1Traffic, Http2Traffic)
    """

    def __init__(self, tshark_output: TsharkOutput):
        self.traffic = tshark_output.list_layers
        self.creation_metadata = {
            "creation_datetime": datetime.now(timezone.utc).isoformat(),
            **tshark_output.metadata,
        }
        self.parsed_traffic: dict[
            type[ParsedTrafficProtocol], ParsedTrafficProtocol
        ] = {}

    def parse_traffic(self) -> None:
        """
        Parse the HTTP1 and HTTP2 network traffic.
        """
        from .protocols import PROTOCOLS

        for protocol_class in PROTOCOLS:
            self.parsed_traffic[protocol_class] = protocol_class(self.traffic)

    def to_har(self) -> dict[str, Any]:
        """
        Convert the network traffic data to HTTP Archive (HAR) format.

        :return: the network traffic data in HAR format
        """
        entries = []
        for parsed_traffic in self.parsed_traffic.values():
            entries.extend(parsed_traffic.get_har_entries())
        entries = sorted(entries, key=itemgetter("_timestamp"))
        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "PiRogue PCAPNG -> HAR",
                    "version": __version__,
                    "_metadata": self.creation_metadata,
                },
                "pages": [],
                "entries": entries,
            }
        }
