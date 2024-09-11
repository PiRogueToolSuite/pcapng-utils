import json
import subprocess
from pathlib import Path


class Tshark:
    """
    A class to interact with tshark for loading and parsing network traffic data from a PCAPNG file.

    **tshark** is a command-line tool for capturing and analyzing network traffic. It is part of the Wireshark suite
    and provides similar functionality to the Wireshark GUI in a terminal environment.
    - Packet capture and analysis: `tshark` can capture live network traffic and analyze packets from capture files (e.g., PCAP, PCAPNG).
    - Protocol decoding: It supports decoding a wide range of network protocols, providing detailed information about each packet.
    - Filtering: `tshark` allows filtering packets using display filters to focus on specific traffic.
    - Statistics: It can generate various statistics about the captured traffic, such as protocol hierarchy, endpoint statistics, and conversation lists.
    - Exporting data: `tshark` can export packet data to different formats, including JSON, CSV, and plain text.
    - Decryption: `tshark` supports decryption of encrypted traffic using SSL/TLS keys provided in an SSLKEYLOG file.

    `tshark` can convert PCAPNG files to JSON format using the `-T json` option. This allows for easy parsing and analysis of network traffic data in a structured format.

    **Useful commands**:
    - Capture live traffic: `tshark -i <interface>`
    - Read from a PCAP file: `tshark -r <file.[pcap|pcapng]>`
    - Display packet details: `tshark -V`
    - Filter packets: `tshark -Y <filter>`
    - Export to JSON: `tshark -r <file.[pcap|pcapng]> -T json`
    - Decrypt SSL/TLS traffic: `tshark -r <file.[pcap|pcapng]> -o "ssl.keys_list: <key_file>"`
    - Inject the TLS secrets: `editcap --inject-secrets tls,<keylog_file> <file.pcap> <output.pcapng>`

    Attributes:
        pcapng_file (Path): The path to the pcapng file to be analyzed.
        tshark_path (str): The path to the tshark executable.
        frames (list): A list to store the frames extracted from the pcapng file.
        request_response_pairs (list): A list to store the request-response pairs.
        traffic (dict): The parsed network traffic data.
    """
    def __init__(self, pcapng_file: Path, tshark_path: str = 'tshark'):
        self.pcapng_file = pcapng_file
        self.tshark_path = tshark_path
        self.frames = []
        self.request_response_pairs = []
        self.traffic = None

    def load_traffic(self):
        """
        Loads network traffic data from a pcapng file using tshark.

        This method runs the tshark command to read the pcapng file and parse the output as JSON.
        The parsed traffic data is then stored in the `traffic` attribute.

        Raises:
            subprocess.CalledProcessError: If the tshark command fails.

        Note that no HTTP3 traffic is expected since it is rejected by Pirogue.
        """
        cmd = f'{self.tshark_path} -2 -r {self.pcapng_file} -x -T json --no-duplicate-keys -Y "http || http2"'
        cmd_output = subprocess.check_output(cmd, shell=True)
        self.traffic = json.loads(cmd_output)
