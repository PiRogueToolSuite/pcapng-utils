import json
from pathlib import Path
from typing import Mapping, Sequence, Any

from . import __version__
from .utils import DictLayers

DictPacket = Mapping[str, Any]


class NetworkTrafficDump:
    """
    The NetworkTrafficDump class is designed to handle and process network traffic data.

    Attributes:
        traffic (list[dict]): A list of dictionaries containing traffic data.
        conversations (list): A list to store conversation data.
        http_traffic (HttpTraffic): An instance of the HttpTraffic class for HTTP traffic.
        http2_traffic (Http2Traffic): An instance of the Http2Traffic class for HTTP/2 traffic.
    """
    def __init__(self, packets: Sequence[DictPacket]):
        self.traffic = self.get_list_layers(packets)
        self.conversations = []
        self.http_traffic = None
        self.http2_traffic = None

    @staticmethod
    def get_list_layers(packets: Sequence[DictPacket]) -> Sequence[DictLayers]:
        """Extract layers: for each packet, it extracts the layers from the `_source` key."""
        return [
            packet['_source']['layers'] for packet in packets
        ]

    def parse_traffic(self) -> None:
        """
        Parse the HTTP and HTTP2 network traffic.
        """
        from pcapng_utils.tshark.protocols.http1 import HttpTraffic
        from pcapng_utils.tshark.protocols.http2 import Http2Traffic
        self.http_traffic = HttpTraffic(self.traffic)
        self.http2_traffic = Http2Traffic(self.traffic)

    def to_har(self) -> dict[str, Any]:
        """
        Convert the network traffic data to HTTP Archive (HAR) format.

        :return: the network traffic data in HAR format
        """
        entries = []
        if self.http_traffic:
            entries.extend(self.http_traffic.get_har_entries())
        if self.http2_traffic:
            entries.extend(self.http2_traffic.get_har_entries())
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
        with output_file.open('w' if overwrite else 'x') as _of:
            json.dump(self.to_har(), _of, indent=indent, **json_dump_kws)
