# SPDX-FileCopyrightText: 2024 Pôle d'Expertise de la Régulation Numérique - PEReN <contact@peren.gouv.fr>
# SPDX-License-Identifier: MIT

import logging
from pathlib import Path
from collections.abc import Set
from typing import Literal, ClassVar, Any

import communityid

from . import HarEnrichment
from .utils import prefix_string_camel_case, clean_prefixed_ip_address

logger = logging.getLogger('enrichment')


class Stacktrace(HarEnrichment):

    ID: ClassVar = 'stacktrace'

    def __init__(self, har_data: dict, input_data_file: Path) -> None:
        super().__init__(har_data, input_data_file)
        self.socket_traces: list[dict] = []

        if self.can_enrich:
            # Preprocess the socket traces: remove unnecessary fields and prefix keys
            self.socket_traces = self._preprocess_socket_traces(self.input_data, prefix='')  # type: ignore
        else:
            logger.warning('HAR enrichment with stacktrace information cannot be performed, skip.')

    @staticmethod
    def _can_enrich_directed_entry(har_directed_entry: dict[str, Any]) -> bool:
        """Check if the given HAR entry can be enriched with stacktrace information"""
        return bool(har_directed_entry.get('_timestamp'))

    @staticmethod
    def _attach_community_id_to_stacktrace(socket_trace_data: dict) -> None:
        """Compute and append in-place the Community ID to the given stacktrace"""
        if 'communityId' in socket_trace_data:  # already done... (TODO: refact)
            return
        cid = communityid.CommunityID()
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
        socket_trace_data['communityId'] = cid.calc(tpl)

    def _find_stacktrace(self, community_id: str, timestamp: float, socket_operations: Set[str]) -> dict:
        """ Find the stacktrace with the closest timestamp to the given one matching the community ID """
        # TODO refact: add once all community IDs + convert as a mapping[cid, sorted_list[(timestamp, socket_data)]]
        best_guess: dict = {}
        min_time = 2. ** 31 - 1
        # The objective is to find the stacktrace by minimizing the time difference between the HAR entry and
        # the stacktrace timestamp
        for socket_trace in self.socket_traces:
            socket_data: dict = socket_trace['data']
            # No stacktrace data, skip
            if 'stack' not in socket_data:
                continue
            self._attach_community_id_to_stacktrace(socket_data)
            # Check if the community ID and the socket operations match
            if socket_data['communityId'] == community_id and socket_data['socketEventType'] in socket_operations:
                trace_timestamp = socket_trace['timestamp']
                delta = abs(trace_timestamp - timestamp)
                if delta < min_time:
                    min_time = delta
                    best_guess = socket_trace
        if best_guess:
            logger.debug(f'Stacktrace found with ∆t={min_time * 1000:.1f}ms, for {community_id} {socket_operations}')
        else:
            logger.warning(f'No stacktrace has been found for {community_id}')
        return best_guess

    @staticmethod
    def _compact_stack_trace(stack_trace: dict) -> list[str]:
        """Compact the stacktrace for convenience"""
        clean_stack = []
        stack = stack_trace['stack']
        for call in stack:
            clazz: str = call['class']
            if clazz not in clean_stack:
                clean_stack.append(clazz)
        return clean_stack

    def _enrich_directed_entry(self, har_entry: dict[str, Any], community_id: str, direction: Literal['in', 'out']) -> None:
        """Attach the stacktrace to the given HAR directed entry (either request or response), in-place"""
        # Fail first
        if direction not in ('in', 'out'):
            raise ValueError(f'Invalid communication direction: {direction}')
        if not self._can_enrich_directed_entry(har_entry):
            return
        # Use read operations on the socket when dealing with a response (in), write operations otherwise
        socket_operations = {'write', 'sendto'} if direction == 'out' else {'read', 'recvfrom'}
        timestamp = float(har_entry['_timestamp'])
        stack_trace = self._find_stacktrace(community_id, timestamp, socket_operations)
        stack_trace_data = stack_trace.get('data', {})
        # Attach the stacktrace to the HAR entry if found
        if stack_trace_data:
            har_entry['_stacktrace'] = stack_trace_data
            har_entry['_stacktrace']['compact'] = self._compact_stack_trace(stack_trace_data)

    def _prefix_keys(self, obj: str | dict | list, prefix: str = '_') -> Any:
        """Prefix all the keys of a dictionary or list of dictionaries recursively"""
        if isinstance(obj, dict):
            empty = {}
            for k, v in obj.items():
                empty[prefix_string_camel_case(k, prefix)] = self._prefix_keys(v, prefix=prefix)
        elif isinstance(obj, list):
            empty = []
            for k in obj:
                empty.append(self._prefix_keys(k, prefix=prefix))
        else:
            empty = obj
        return empty

    def _clean_stacktrace_data(self, stacktrace: dict, prefix: str = '') -> dict:
        """
        Clean the stacktrace data by removing unnecessary fields, prefixing keys if necessary and ensure the
        timestamp is in seconds.

        <!> do not run twice!
        """
        stacktrace['timestamp'] /= 1000.
        del stacktrace['type']
        del stacktrace['data_type']
        del stacktrace['dump']
        del stacktrace['pid']
        # Prefix the keys of the stacktrace data
        processed_stacktrace = self._prefix_keys(stacktrace, prefix=prefix)
        return processed_stacktrace

    def _preprocess_socket_traces(self, socket_traces: list[dict], prefix: str = '') -> list[dict]:
        return [
            self._clean_stacktrace_data(socket_trace, prefix)
            for socket_trace in socket_traces
        ]

    def enrich_entry(self, har_entry: dict[str, Any]) -> None:
        """Enrich the HAR data with the stacktraces information"""
        community_id = har_entry.get('_communityId')
        if not community_id:
            return
        self._enrich_directed_entry(har_entry['request'], community_id, direction='out')
        self._enrich_directed_entry(har_entry['response'], community_id, direction='in')
