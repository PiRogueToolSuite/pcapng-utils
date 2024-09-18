import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

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
            'creation_datetime': datetime.now(timezone.utc).isoformat(),
            **tshark_output.metadata
        }
        self.parsed_traffic: dict[type[ParsedTrafficProtocol], ParsedTrafficProtocol] = {}

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
        from . import __version__

        entries = []
        for parsed_traffic in self.parsed_traffic.values():
            entries.extend(parsed_traffic.get_har_entries())
        entries = sorted(entries, key=lambda x: x['timestamp'])
        return {
            'log': {
                'version': '1.2',
                'creator': {
                    'name': 'PiRogue PCAPNG -> HAR',
                    'version': __version__,
                    'comment': json.dumps(self.creation_metadata),
                },
                'pages': [],
                'entries': entries
            }
        }

    def save_har(
        self, output_file: Path, *, overwrite: bool = False, indent: int = 2, **json_dump_kws: Any
    ) -> None:
        """
        Save the network traffic data in HAR format to a file.

        :param output_file: the file to save the HAR data to
        """
        har_content = self.to_har()  # fail before creating/overwriting file
        with output_file.open('w' if overwrite else 'x') as fp:
            json.dump(har_content, fp, indent=indent, **json_dump_kws)
