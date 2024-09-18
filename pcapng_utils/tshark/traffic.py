import json
from pathlib import Path
from typing import Sequence, Any

from .types import DictPacket, DictLayers, ParsedTrafficProtocol


class NetworkTrafficDump:
    """
    The NetworkTrafficDump class is designed to handle and process network traffic data.

    Attributes:
        traffic (list[dict]): A list of dictionaries containing traffic data.
        conversations (list): A list to store conversation data.
        parsed_traffic[class, instance]: Mapping of parsed traffic per protocol class
        (e.g. Http1Traffic, Http2Traffic)
    """
    def __init__(self, packets: Sequence[DictPacket]):
        self.traffic = self.get_list_layers(packets)
        self.conversations = []
        self.parsed_traffic: dict[type[ParsedTrafficProtocol], ParsedTrafficProtocol] = {}

    @staticmethod
    def get_list_layers(packets: Sequence[DictPacket]) -> Sequence[DictLayers]:
        """Extract layers: for each packet, it extracts the layers from the `_source` key."""
        assert isinstance(packets, Sequence), type(packets)
        return [
            packet['_source']['layers'] for packet in packets
        ]

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
                    'name': 'PiRogue',
                    'version': __version__,
                    'comment': 'PiRogue HTTP Traffic HAR'
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
