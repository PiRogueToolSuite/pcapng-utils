# SPDX-FileCopyrightText: 2024 Pôle d'Expertise de la Régulation Numérique - PEReN <contact@peren.gouv.fr>
# SPDX-License-Identifier: MIT

import logging
from pathlib import Path
from operator import itemgetter
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TypedDict, Literal, ClassVar, Any

import communityid
from sortedcontainers import SortedKeyList

from .base import HarEnrichment
from .types import CommunityID, Timestamp, FlowDirection
from .utils import keys_to_camel_case, clean_prefixed_ip_address
from .sorted_list import get_closest_in_window

logger = logging.getLogger('enrichment')


class SocketTraceData(TypedDict):
    timestamp: Timestamp  # seconds
    process: str
    pid: int
    stack: list[dict]
    socketEventType: str
    localIp: str
    localPort: int
    destIp: str
    destPort: int
    socketType: Literal['tcp', 'tcp6', 'udp', 'udp6']
    communityId: CommunityID


def empty_time_sorted_list_of_stack_traces():
    return SortedKeyList(key=itemgetter('timestamp'))


@dataclass(frozen=True)
class HAREntryMetadata:
    community_id: CommunityID
    direction: FlowDirection
    timestamp: Timestamp
    entry_id: str  # `_sha1Id` field
    is_http2: bool


class Stacktrace(HarEnrichment):

    ID: ClassVar = 'stacktrace'

    COMMUNITY_ID: ClassVar = communityid.CommunityID()

    KEYS_PREFIX: ClassVar[str] = ''
    TIME_WINDOWS: ClassVar[Mapping[FlowDirection, tuple[float, float]]] = {
        'out': (-5.0, 0.1),
        'in':  (-0.1, 5.0),
    }
    """
    Tolerances (in seconds) regarding chronology of socket operations compared to network traffic (per flow direction).

    - For outbound network traffic, the socket operation shall be in the past, or a very very close future,
    - For inbound network traffic, it is the opposite.
    """

    DO_NOT_EXPORT_STACKTRACE_KEYS: ClassVar = {
        # redundant
        'communityId',
        'destIp',
        'destPort',
        'localIp',
        'localPort',
    }

    def __init__(self, har_data: dict, input_data_file: Path) -> None:
        super().__init__(har_data, input_data_file)
        self.socket_traces_map: Mapping[tuple[CommunityID, FlowDirection], SortedKeyList] = defaultdict(empty_time_sorted_list_of_stack_traces)
        self.paired_socket_traces: dict[tuple[CommunityID, FlowDirection, int], HAREntryMetadata] = {}

        if self.can_enrich:
            self._preprocess_socket_traces()

    @classmethod
    def _attach_community_id_to_stacktrace(cls, socket_trace_data: dict) -> None:
        """Compute and append in-place the Community ID to the given stacktrace"""
        src_ip = clean_prefixed_ip_address(socket_trace_data['localIp'])
        src_port = socket_trace_data['localPort']
        dst_ip = clean_prefixed_ip_address(socket_trace_data['destIp'])
        dst_port = socket_trace_data['destPort']
        # Prepare the Community ID template based on the protocol
        if 'tcp' in socket_trace_data['socketType']:
            tpl = communityid.FlowTuple.make_tcp(src_ip, dst_ip, src_port, dst_port)
        else:
            tpl = communityid.FlowTuple.make_udp(src_ip, dst_ip, src_port, dst_port)
        # Attach the Community ID
        socket_trace_data['communityId'] = cls.COMMUNITY_ID.calc(tpl)

    @classmethod
    def _get_clean_stacktrace(cls, stacktrace: dict) -> SocketTraceData:
        """
        Get a clean stacktrace object by removing unnecessary fields,
        renaming keys in camel case (with optional prefix) and ensuring the
        timestamp is in seconds (instead of milliseconds).

        Side-effects free.
        """
        clean_trace_data = keys_to_camel_case({
            'timestamp': stacktrace['timestamp'] / 1000.,
            'process': stacktrace['process'],
            **stacktrace['data'],
        }, prefix=cls.KEYS_PREFIX)
        cls._attach_community_id_to_stacktrace(clean_trace_data)
        return clean_trace_data  # type: ignore[return-value]

    def _preprocess_socket_traces(self) -> None:
        """Create the mapping of stock traces (by community ID + flow direction) to efficiently attach them afterwards."""
        assert isinstance(self.input_data, list), type(self.input_data)
        for raw_stack_trace in self.input_data:
            clean_stack_trace = self._get_clean_stacktrace(raw_stack_trace)
            socket_type = clean_stack_trace['socketEventType']
            # Use read operations on the socket when dealing with a response (in), write operations otherwise (out)
            flow_dir: FlowDirection | None = 'out' if socket_type in {'write', 'sendto'} else 'in' if socket_type in {'read', 'recvfrom'} else None
            if flow_dir is None:
                continue
            # TODO: check that timestamp != of others?
            self.socket_traces_map[(clean_stack_trace['communityId'], flow_dir)].add(clean_stack_trace)

    def _find_best_stacktrace(self, har: HAREntryMetadata) -> SocketTraceData | None:
        r"""
        Find the stacktrace with the closest\* timestamp to the given one matching the community ID

        \* (in the past if direction is `out`, in the future if direction was `in`)
        """
        matching_traces = self.socket_traces_map.get((har.community_id, har.direction))
        if not matching_traces:
            logger.warning(f'No socket operation has been found for {har}')
            return None
        if (closest := get_closest_in_window(matching_traces, har.timestamp, self.TIME_WINDOWS[har.direction])) is None:
            socket_chronology = 'just before' if har.direction == 'out' else 'just after'
            logger.warning(f'No socket operation has been found {socket_chronology} {har}')
            return None
        closest_socket_data: SocketTraceData
        closest_socket_ix, closest_socket_timestamp, closest_socket_data = closest
        current_delta_sec = har.timestamp - closest_socket_timestamp
        pairing_key = (har.community_id, har.direction, closest_socket_ix)
        already_paired_har = self.paired_socket_traces.get(pairing_key)
        if already_paired_har is not None:
            if already_paired_har.timestamp == har.timestamp:
                # OK: multiple HTTP2 streams in 1 network frame (and thus 1 socket call)
                assert already_paired_har.is_http2 and har.is_http2, (har, already_paired_har)
            else:
                # we could raise but this happens in real life...
                # TODO? find best OVERALL allocations of socket operations instead of FIFO?
                logger.warning(
                    f'Pairing {har} with socket operation @ {closest_socket_timestamp:.3f}, '
                    f'but it is also paired with {already_paired_har}...'
                )
        self.paired_socket_traces[pairing_key] = har
        logger.debug(f'Stacktrace found with ∆t={current_delta_sec * 1000:.1f}ms for {har}')
        return closest_socket_data

    @staticmethod
    def _compact_stack_trace(stack_trace: SocketTraceData) -> list[str] | None:
        """Compact the stacktrace for convenience"""
        if 'stack' not in stack_trace:  # this happens...
            return None
        # order of dictionary keys is officially guaranteed since Python >= 3.7
        return list({call['class']: 0 for call in stack_trace['stack']})

    def _enrich_directed_entry(
        self, har_entry: dict[str, Any], community_id: CommunityID, direction: FlowDirection, *, har_entry_id: str
    ) -> None:
        """Attach the stacktrace to the given HAR directed entry (either request or response), in-place"""
        # Fail first
        if direction not in ('in', 'out'):
            raise ValueError(f'Invalid communication direction: {direction}')
        # <!> we always expect the `har_entry` to have out-of-specs `_timestamp: float` key
        # but it may be None (missing response)
        if har_entry['_timestamp'] is None:
            return
        stack_trace = self._find_best_stacktrace(
            HAREntryMetadata(
                community_id,
                direction,
                Timestamp(har_entry['_timestamp']),
                # useful metadata when debugging
                har_entry_id,
                har_entry['httpVersion'] == 'HTTP/2',
            )
        )
        # Attach the stacktrace to the HAR entry if found
        if stack_trace:
            har_entry['_stacktrace'] = {'stack': None} | {
                k: v for k, v in stack_trace.items() if k not in self.DO_NOT_EXPORT_STACKTRACE_KEYS
            } | {'compact': self._compact_stack_trace(stack_trace)}

    def enrich_entry(self, har_entry: dict[str, Any]) -> None:
        """Enrich the HAR data with the stacktraces information"""
        # <!> we expect our out-of-specs fields: _communityId & _sha1Id & _timestamp
        community_id = har_entry['_communityId']
        har_entry_id = har_entry['_sha1Id']
        self._enrich_directed_entry(har_entry['request'], community_id, direction='out', har_entry_id=har_entry_id)
        self._enrich_directed_entry(har_entry['response'], community_id, direction='in', har_entry_id=har_entry_id)
