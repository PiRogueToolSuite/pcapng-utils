# SPDX-FileCopyrightText: 2024 Pôle d'Expertise de la Régulation Numérique - PEReN <contact@peren.gouv.fr>
# SPDX-License-Identifier: MIT

import json
from pathlib import Path
from typing import Any

import communityid

from pcapng_utils.tshark.enrichment import Enrichment
from pcapng_utils.tshark.utils import prefix_string_camel_case, clean_prefixed_ip_address


class Stacktrace(Enrichment):
    def __init__(self, har_data: dict, data_file: Path):
        super().__init__(har_data, data_file)
        self.socket_traces = []

        if not data_file.exists() or not data_file.is_file():
            raise ValueError(f"Invalid stacktrace file: {data_file}")

        # Load the operations on sockets and their associated stack traces
        with data_file.open('r') as f:
            socket_traces: list[dict] = json.load(f)
        if socket_traces:
            # Preprocess the socket traces: remove unnecessary fields and prefix keys
            self.socket_traces = self._preprocess_socket_traces(socket_traces, prefix='')

    @staticmethod
    def _can_enrich(har_entry: dict) -> bool:
        """Check if the given HAR entry can be enriched with stacktrace information"""
        if not har_entry:
            return False
        timestamp = har_entry.get('_timestamp', None)
        if not timestamp:
            return False
        return True

    @staticmethod
    def _attach_community_id_to_stacktrace(socket_trace: dict):
        """Compute and append the Community ID to the given stacktrace"""
        cid = communityid.CommunityID()
        socket_trace_data: dict = socket_trace['data']
        src_ip = clean_prefixed_ip_address(socket_trace_data.get('localIp'))
        src_port = socket_trace_data.get('localPort')
        dst_ip = clean_prefixed_ip_address(socket_trace_data.get('destIp'))
        dst_port = socket_trace_data.get('destPort')
        # Prepare the Community ID template based on the protocol
        if 'tcp' in socket_trace['data']['socketType']:
            tpl = communityid.FlowTuple.make_tcp(src_ip, dst_ip, src_port, dst_port)
        else:
            tpl = communityid.FlowTuple.make_udp(src_ip, dst_ip, src_port, dst_port)
        # Attach the Community ID
        socket_trace_data.update({
            'communityId': cid.calc(tpl)
        })

    def _find_stacktrace(self, community_id: str, timestamp: float, socket_operations: list[str]) -> dict:
        """ Find the stacktrace with the closest timestamp to the given one matching the community ID """
        best_guess = None
        min_time = 9999999999.
        for socket_trace in self.socket_traces:
            socket_data = socket_trace['data']
            if 'stack' not in socket_data:
                continue
            self._attach_community_id_to_stacktrace(socket_trace)
            if socket_data['communityId'] == community_id and socket_data['socketEventType'] in socket_operations:
                trace_timestamp = socket_trace['timestamp']
                delta = abs(trace_timestamp - timestamp)
                if delta < min_time:
                    min_time = delta
                    best_guess = socket_trace
        return best_guess

    @staticmethod
    def _compact_stack_trace(stack_trace: dict) -> list[str]:
        """Compact the stacktrace for convenience"""
        clean_stack = []
        stack = stack_trace['data']['stack']
        for call in stack:
            clazz = call.get('class')
            if clazz not in clean_stack:
                clean_stack.append(clazz)
        return clean_stack

    def _enrich_entry(self, har_entry: dict, community_id: str, direction: str) -> dict:
        """Attack the stacktrace to the given HAR entry (either request or response)"""
        if not self._can_enrich(har_entry):
            return har_entry
        # Use read operations on the socket when dealing with a response, write operations otherwise
        socket_operations = ['write', 'sendto'] if direction == 'out' else ['read', 'recvfrom']
        timestamp = float(har_entry['_timestamp'])
        stack_trace = self._find_stacktrace(community_id, timestamp, socket_operations)
        if stack_trace:
            har_entry['_stacktrace'] = stack_trace.get('data', None)
            har_entry['_stacktrace']['compact'] = self._compact_stack_trace(stack_trace)
        return har_entry

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
        """
        stacktrace['timestamp'] = stacktrace['timestamp'] / 1000.
        del stacktrace['type']
        del stacktrace['data_type']
        del stacktrace['dump']
        del stacktrace['pid']
        # Prefix the keys of the stacktrace data
        processed_stacktrace = self._prefix_keys(stacktrace, prefix=prefix)
        return processed_stacktrace

    def _preprocess_socket_traces(self, socket_traces: list[dict], prefix: str = '') -> list:
        return [
            self._clean_stacktrace_data(socket_trace, prefix)
            for socket_trace in socket_traces
        ]

    def enrich(self):
        """Enrich the HAR data with the stacktraces information"""
        if not self.socket_traces:
            return
        for entry in self.har_data['log']['entries']:
            community_id = entry.get('_communityId')
            entry['request'] = self._enrich_entry(entry.get('request'), community_id, direction='out')
            entry['response'] = self._enrich_entry(entry.get('response'), community_id, direction='in')
