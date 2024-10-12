import json
import subprocess
from pathlib import Path
from hashlib import file_digest
from functools import cached_property
from dataclasses import dataclass
from typing import Sequence, Mapping, Any

from .types import DictPacket, DictLayers


@dataclass(frozen=True)
class TsharkOutput:
    """Output of tshark network traffic dump, together with some metadata of about it."""

    list_packets: Sequence[DictPacket]
    metadata: Mapping[str, Any]

    def __post_init__(self) -> None:
        assert isinstance(self.list_packets, Sequence), type(self.list_packets)

    @property
    def list_layers(self) -> Sequence[DictLayers]:
        """Extract layers: for each packet, it extracts the layers from the `_source` key."""
        return [
            packet['_source']['layers'] for packet in self.list_packets
        ]


@dataclass(frozen=True)
class Tshark:
    """
    A class to interact with tshark for loading and parsing network traffic data from a PCAPNG file.

    **tshark** is a command-line tool for capturing and analyzing network traffic.
    It is part of the Wireshark suite and provides similar functionality to the Wireshark GUI in a terminal environment.
    - Packet capture and analysis: `tshark` can capture live network traffic and analyze packets from capture files (e.g., PCAP, PCAPNG).
    - Protocol decoding: It supports decoding a wide range of network protocols, providing detailed information about each packet.
    - Filtering: `tshark` allows filtering packets using display filters to focus on specific traffic.
    - Statistics: It can generate various statistics about the captured traffic, such as protocol hierarchy, endpoint statistics, and conversation lists.
    - Exporting data: `tshark` can export packet data to different formats, including JSON, CSV, and plain text.
    - Decryption: `tshark` supports decryption of encrypted traffic using SSL/TLS keys provided in an SSLKEYLOG file.

    `tshark` can convert PCAPNG files to JSON format using the `-T json` option.
    This allows for easy parsing and analysis of network traffic data in a structured format.

    **Useful commands**:
    - Capture live traffic: `tshark -i <interface>`
    - Read from a PCAP file: `tshark -r <file.[pcap|pcapng]>`
    - Display packet details: `tshark -V`
    - Filter packets: `tshark -Y <filter>`
    - Export to JSON: `tshark -r <file.[pcap|pcapng]> -T json`
    - Decrypt SSL/TLS traffic: `tshark -r <file.[pcap|pcapng]> -o "ssl.keys_list: <key_file>"`
    - Inject the TLS secrets: `editcap --inject-secrets tls,<keylog_file> <file.pcap> <output.pcapng>`

    Attributes:
        tshark_cmd (str): The path to the tshark executable.
    """
    tshark_cmd: str = 'tshark'
    hash_algo: str = 'sha1'

    @cached_property
    def version(self) -> str:
        proc = subprocess.run([self.tshark_cmd, '--version'], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr)
        version_first_line = proc.stdout.splitlines()[0].strip()
        return version_first_line.removeprefix('TShark (Wireshark) ').removesuffix('.')

    def load_traffic(self, pcapng_file: Path) -> TsharkOutput:
        """
        Loads network traffic data from the provided pcapng file using tshark.

        This method runs the tshark command to read the pcapng file and parse the output as JSON.
        The parsed traffic data is then returned, together with some metadata.

        Raises:
            subprocess.CalledProcessError: If the tshark command fails.

        Note that no HTTP3 traffic is expected since it is rejected by Pirogue.
        """
        with pcapng_file.open('rb') as fp:
            metadata = {
                'tshark_version': self.version,
                f'input_{self.hash_algo}': file_digest(fp, self.hash_algo).hexdigest(),
            }
        cmd = [
            self.tshark_cmd,
            '-2',  # two passes
            '-r', pcapng_file.as_posix(),
            '-x',  # output raw fields as well
            '-T', 'json',
            '-NdnN',  # name resolution
            '--no-duplicate-keys',  # merge json keys
            '-Y', 'http || http2',  # display filters
            '-J', 'frame ip tcp http http2',  # do not export data of useless layers
            '--enable-protocol', 'communityid',
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.decode())
        list_packets = json.loads(proc.stdout)
        return TsharkOutput(list_packets, metadata)
