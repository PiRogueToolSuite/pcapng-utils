import base64
import binascii
import json
from pathlib import Path


class NetworkTrafficDump:
    """
    The NetworkTrafficDump class is designed to handle and process network traffic data.

    Attributes:
        traffic (list[dict]): A list of dictionaries containing traffic data.
        conversations (list): A list to store conversation data.
        http_traffic (HttpTraffic): An instance of the HttpTraffic class for HTTP traffic.
        http2_traffic (Http2Traffic): An instance of the Http2Traffic class for HTTP/2 traffic.
    """
    def __init__(self, traffic: list[dict]):
        self.traffic = traffic
        self.conversations = []
        self.http_traffic = None
        self.http2_traffic = None

    def get_packets(self) -> list[dict]:
        """
        Get the traffic data stored in the traffic attribute.

        :return: the traffic data.
        """
        return self.traffic

    @staticmethod
    def hex_content_to_base64(content: str):
        """
        Convert hexadecimal content to base64-encoded string.

        :param content: the hexadecimal content to be converted
        :return: the base64-encoded string. If the input content is not valid hexadecimal,
                 the original content is returned.
        """
        try:
            bin_content = binascii.unhexlify(content.replace(':', ''))
        except binascii.Error:
            return content
        base64_bytes = base64.b64encode(bin_content)
        return base64_bytes.decode('ascii')

    @staticmethod
    def decode_data(content, printable=True, json_indent=2) -> str:
        """
        Decodes hexadecimal content into a human-readable string.

        :param content: the hexadecimal content to be decoded
        :param printable: if True, attempts to decode the content to a printable string.
        :param json_indent: the number of spaces to indent JSON data.
        :return: the decoded content. If the input content is not valid hexadecimal, the original content is returned.
        """
        if not content:
            return ''
        if ':' not in content:
            return content
        try:
            bin_content = binascii.unhexlify(content.replace(':', ''))
        except binascii.Error:
            return content
        decoded: str = ''
        if printable:
            try:
                decoded = bin_content.decode('utf-8')
            except UnicodeDecodeError:
                pass
            if decoded and decoded.isprintable():
                try:
                    decoded = base64.b64decode(decoded).decode('ascii')
                except:
                    pass
                try:
                    data = json.loads(decoded)
                    return json.dumps(data, indent=json_indent)
                except json.JSONDecodeError:
                    return decoded
        if decoded and decoded.isprintable():
            return decoded
        base64_bytes = base64.b64encode(bin_content)
        return base64_bytes.decode('ascii')

    def get_packet_by_number(self, frame_number: int):
        """
        Get a packet by frame number.

        :param frame_number: the frame number of the packet to retrieve
        :return: the packet layers if found, otherwise None.
        """
        if frame_number < 0:
            return None
        for packet in self.traffic:
            if packet.get('_source').get('layers').get('frame').get('frame.number') == str(frame_number):
                return packet.get('_source').get('layers')
        return None

    def parse_traffic(self):
        """
        Parse the HTTP and HTTP2 network traffic.
        """
        from pcapng_utils.tshark.protocols.http1 import HttpTraffic
        from pcapng_utils.tshark.protocols.http2 import Http2Traffic
        self.http_traffic = HttpTraffic(self)
        self.http2_traffic = Http2Traffic(self)

    def to_har(self):
        """
        Convert the network traffic data to HTTP Archive (HAR) format.

        :return: the network traffic data in HAR format
        """
        entries = []
        if self.http_traffic:
            entries.extend(self.http_traffic.get_har_entries())
        if self.http2_traffic:
            entries.extend(self.http2_traffic.get_har_entries())
        entries = sorted(entries, key=lambda x: x.get('timestamp'))
        return {
            'log': {
                'version': '1.2',
                'creator': {
                    'name': 'PiRogue',
                    'version': '0.1',
                    'comment': 'PiRogue HTTP Traffic HAR'
                },
                'pages': [],
                'entries': entries
            }
        }

    def save_har(self, output_file: Path):
        """
        Save the network traffic data in HAR format to a file.

        :param output_file: the file to save the HAR data to
        """
        with output_file.open('w') as _of:
            json.dump(self.to_har(), _of, indent=2)
