import json
import logging
import subprocess
import shlex
import re
import platform
from pathlib import Path
from hashlib import file_digest
from functools import cached_property
from dataclasses import dataclass, KW_ONLY
from collections.abc import Sequence, Mapping
from typing import Any, Literal, Annotated

import tyro

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


LOGGER = logging.getLogger("pcapng_utils.tshark")

DEFAULT_HOSTS_FILE = h if (h := Path("/etc/hosts")).is_file() else None

DEFAULT_TSHARK_CMD = {
    "Linux": "/usr/bin/tshark",
    "Darwin": "/Applications/Wireshark.app/Contents/MacOS/tshark",
}.get(platform.system(), "tshark")


@dataclass(frozen=True)
class Tshark:
    """
    A class to interact with tshark for loading and parsing network traffic data from a PCAPNG file.

    **tshark** is a command-line tool for capturing and analyzing network traffic.
    It is part of the Wireshark suite and provides similar functionality to the Wireshark GUI in a terminal environment.

    - Packet capture and analysis: `tshark` can capture live network traffic and analyze packets from capture files (e.g., PCAP, PCAPNG).
    - Protocol decoding: It supports decoding a wide range of network protocols, providing detailed information about each packet.
    - Filtering: `tshark` allows filtering packets using display filters to focus on specific traffic.
    - Statistics: It can generate various statistics about the captured traffic, such as protocol hierarchy,
    endpoint statistics, and conversation lists.
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
    """

    tshark_cmd: Annotated[str, tyro.conf.arg(name='tshark', aliases=['-c'], metavar='CMD')] = DEFAULT_TSHARK_CMD
    """Path/command for tshark executable"""

    _: KW_ONLY

    hash_algo: Annotated[str, tyro.conf.arg(metavar='ALGO')] = 'sha1'
    """Hash algorithm to generate digest of input .pcapng"""

    name_resolution: Annotated[Literal[False] | str, tyro.conf.arg(metavar='FLAGS|False')] = 'nds'
    """Name resolution flags, as documented in tshark manual under -N flag;
    by default we avoid using any external DNS resolver"""

    hosts_file: Path | None = DEFAULT_HOSTS_FILE
    """Hosts file for tshark name resolution - only used when name resolution contains'n'"""

    display_filter: Annotated[str, tyro.conf.arg(aliases=['-Y'])] = "http || http2 || websocket"
    """Display filter (documented in tshark manual under -Y flag)"""

    protocol_match_filter: Annotated[str, tyro.conf.arg(aliases=['-J'])] = "http http2 websocket"
    """Protocol match filter (documented in tshark manual under -J flag), in addition to base protocols"""

    tcp_reassemble_out_of_order: bool = True
    """Whether to allow or not to reassemble out-of-order TCP segments"""

    timeout: Annotated[float, tyro.conf.arg(metavar='SECONDS')] = 60.0
    """Timeout in seconds for tshark command completion"""

    @cached_property
    def _tshark_cmd_split(self) -> list[str]:
        return shlex.split(self.tshark_cmd)

    @cached_property
    def version(self) -> str:
        proc = subprocess.run(
            [*self._tshark_cmd_split, '--version'], text=True, capture_output=True, timeout=self.timeout
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr)
        VERSION_LINE_PREFIX = 'TShark (Wireshark) '
        version_first_line = next(line for line in proc.stdout.splitlines() if line.startswith(VERSION_LINE_PREFIX))
        version = version_first_line.removeprefix(VERSION_LINE_PREFIX).removesuffix('.')
        if not version.startswith("4."):
            raise NotImplementedError(f"Unsupported tshark version (expected v4.x): {version}")
        return version

    @cached_property
    def less_than_v4_4(self) -> bool:
        # no version parsing for now
        for minor in range(4):
            if self.version.startswith(f"4.{minor}."):
                return True
        return False

    def get_command(self, pcapng_file: Path) -> list[str]:
        """Get full command to be executed"""
        name_resolution_flags = list[str]()
        if not self.name_resolution:
            name_resolution_flags.append('-n')
        else:
            name_resolution = self.name_resolution
            if 's' in name_resolution and self.less_than_v4_4:
                # name resolution from SNI only supported in tshark >=4.4
                name_resolution = name_resolution.replace('s', '')
            name_resolution_flags += ['-N', name_resolution]
            if 'n' in name_resolution and self.hosts_file:
                name_resolution_flags += ['-H', self.hosts_file.as_posix()]
        return [
            *self._tshark_cmd_split,
            '-r', pcapng_file.resolve().as_posix(),
            '-2',  # two passes (can't read from stdin in this case)
            '-x',  # output raw fields as well
            '-T', 'json',
            '--no-duplicate-keys',  # merge json keys
            *name_resolution_flags,
            '-Y', self.display_filter,
            '-J', f'frame ip ipv6 tcp {self.protocol_match_filter}',  # do not export data of useless layers
            '--enable-protocol', 'communityid',
            '-o', f'tcp.reassemble_out_of_order:{str(self.tcp_reassemble_out_of_order).upper()}',
        ]

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
        cmd = self.get_command(pcapng_file)
        LOGGER.debug(f"Command for tshark {self.version}: {cmd}")
        proc = subprocess.run(cmd, capture_output=True, timeout=self.timeout)
        if proc.returncode != 0:
            err = list[str]()
            if proc.stderr:
                err.append(proc.stderr.decode())
            if proc.stdout:
                err.append(proc.stdout.decode())
            raise RuntimeError("\n".join(err))
        # We remove any leading/trailing information between actual tshark output
        # (e.g. from OCI container prologue)
        out = proc.stdout.strip()
        if not out.startswith(b"["):
            out = re.sub(rb"^[^\[]+\[", b"[", out)
        if not out.endswith(b"]"):
            out = re.sub(rb"\][^\]]+$", b"]", out)
        list_packets = json.loads(out)
        return TsharkOutput(list_packets, metadata)


def cli_dump_tshark_layers_as_json() -> None:
    """Standard output may be redirected to a .json to inspect tshark intermediate output"""

    import sys
    from pprint import pprint

    @dataclass(frozen=True, kw_only=True)
    class TsharkCli(Tshark):
        pcapng_file: Annotated[Path, tyro.conf.arg(aliases=["-i"], metavar="PATH")]
        """Path to input .pcapng"""

    TsharkCli.__doc__ = Tshark.__doc__

    tshark = tyro.cli(TsharkCli, config=(tyro.conf.DisallowNone,))
    out = tshark.load_traffic(tshark.pcapng_file)

    pprint(out.metadata, stream=sys.stderr, indent=2, width=100)
    print(json.dumps(out.list_layers, ensure_ascii=False, allow_nan=False, indent=2))


if __name__ == "__main__":
    cli_dump_tshark_layers_as_json()
