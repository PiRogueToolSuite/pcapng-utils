from abc import ABC, abstractmethod
from datetime import datetime
from functools import cached_property
from dataclasses import dataclass
from typing import Sequence, Optional, Any

import pytz

from pcapng_utils.tshark.utils import Payload, DictLayers, get_layers_mapping

HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'}


@dataclass(frozen=True)
class HttpRequestResponse(ABC):
    """
    Base class for HTTP request and response packets. It wraps the packet data and provides methods to
    access the relevant information.
    """
    packet: DictLayers

    @property
    def http_layer(self) -> dict[str, Any]:
        return self.packet['http']

    @property
    @abstractmethod
    def _raw_headers(self) -> str | list[str]:
        pass

    @property
    def raw_headers(self) -> Sequence[str]:
        header_or_list_headers = self._raw_headers
        if not isinstance(header_or_list_headers, list):
            assert isinstance(header_or_list_headers, str), header_or_list_headers
            header_or_list_headers = [header_or_list_headers]
        return header_or_list_headers

    @property
    def header_length(self) -> int:
        return len(''.join(self.raw_headers))

    @property
    def content_type(self) -> str:
        return self.http_layer.get('http.content_type', '')

    @property
    def raw_hex_content(self) -> str:
        # data is [hex_str, *sizes]
        return self.http_layer.get('http.file_data_raw', [''])[0]

    @cached_property
    def payload(self) -> Payload:
        return Payload.from_unsure_tshark_data(self.raw_hex_content)

    @property
    def content_length(self) -> int:
        return self.payload.size

    @property
    def started_date(self) -> str:
        frame_time: str = self.packet['frame']['frame.time_epoch']
        return datetime.fromtimestamp(float(frame_time), pytz.utc).isoformat()

    @property
    def headers(self) -> list[dict[str, str]]:
        assert isinstance(self.raw_headers, list), self.raw_headers
        processed_headers = []
        for header in self.raw_headers:
            assert header.isascii(), header
            key_value = header.split(':', 1) # on rare occasions there is no space after :
            assert len(key_value) == 2, key_value
            key, value = key_value
            processed_headers.append({
                'name': key.strip(),
                'value': value.replace('\r\n', '').strip()
            })
        return processed_headers


@dataclass(frozen=True)
class HttpRequest(HttpRequestResponse):
    """
    Class to represent an HTTP request.
    """
    @property
    def _raw_headers(self) -> str | list[str]:
        return self.http_layer.get('http.request.line', [])

    @cached_property
    def method(self) -> Optional[str]:
        """
        Get the HTTP method from the packet data.
        :return: the HTTP method
        """
        for v in self.http_layer.values():
            if isinstance(v, dict) and 'http.request.method' in v:
                meth = v['http.request.method']
                assert meth in HTTP_METHODS, meth
                return meth
        return None

    @property
    def sending_duration(self):
        return round(1000 * float(self.packet['frame'].get('frame.time_delta', 0)), 2)

    def to_har(self) -> dict[str, Any]:
        """
        Convert the HTTP request to HTTP Archive (HAR) format.
        :return: the HTTP request in HAR format
        """
        d = {
            'startedDateTime': self.started_date,
            'method': self.method,
            'url': self.uri,
            'httpVersion': 'HTTP/1.1',
            'headers': self.headers,
            'queryString': [], # TODO?
            'cookies': [], # TODO?
            'headersSize': self.header_length,
            'bodySize': self.content_length,
        }
        if self.content_length:
            d['postData'] = {
                'mimeType': self.content_type,
                **self.payload.to_har_dict(),
            }
        return d

    @property
    def uri(self) -> str:
        return self.http_layer.get('http.request.full_uri', '')

    @property
    def src_host(self) -> str:
        return self.packet['ip'].get('ip.src_host', '')

    @property
    def dst_host(self) -> str:
        return self.packet['ip'].get('ip.dst_host', '')

    @property
    def src_ip(self) -> str:
        return self.packet['ip'].get('ip.src', '')

    @property
    def dst_ip(self) -> str:
        return self.packet['ip'].get('ip.dst', '')


@dataclass(frozen=True)
class HttpResponse(HttpRequestResponse):
    """
    Class to represent an HTTP response.
    """
    @property
    def _raw_headers(self) -> str | list[str]:
        return self.http_layer.get('http.response.line', [])

    @cached_property
    def status_code_message(self) -> tuple[int, str]:
        """
        Parse the HTTP status line from the packet data.
        :return: the HTTP status code and message
        """
        line = ''
        for k, _ in self.http_layer.items():
            if k.startswith('HTTP/'):
                line = k
            elif k.startswith(' [truncated]'):
                line = k.removeprefix(' [truncated]') + ' HTTP/1.1'
            elif k.split(' ')[0] in HTTP_METHODS:
                line = k
        parts = line.split(' ', 2)
        if len(parts) == 3:
            status_code = int(parts[1].strip())
            status_message = parts[2].removesuffix('\\r\\n')
            return status_code, status_message
        return 0, ''

    def to_har(self):
        """
        Convert the HTTP response to HTTP Archive (HAR) format.
        :return: the HTTP response in HAR format
        """
        status_code, status_message = self.status_code_message
        return {
            'startedDateTime': self.started_date,
            'status': status_code,
            'statusText': status_message,
            'httpVersion': 'HTTP/1.1',
            'headers': self.headers,
            'cookies': [],  # TODO?
            'headersSize': self.header_length,
            'bodySize': self.content_length,
            'content': {
                'mimeType': self.content_type,
                **self.payload.to_har_dict(),
            }
        }

    @property
    def receiving_duration(self) -> float:
        return round(1000 * float(self.http_layer.get('http.time', 0)), 2)


class HttpConversation:
    """
    Class to represent an HTTP conversation composed of a request and a response.
    """
    def __init__(self, request_layers: DictLayers, response_layers: DictLayers):
        self.request = HttpRequest(request_layers)
        self.response = HttpResponse(response_layers)

    @property
    def request_timestamp(self) -> float:
        return float(self.request.packet['frame']['frame.time_epoch'])

    @property
    def waiting_duration(self) -> float:
        start_time = self.request_timestamp
        stop_time = float(self.response.packet['frame']['frame.time_epoch'])
        return round(1000 * (stop_time - start_time), 2)

    def to_har(self) -> dict[str, Any]:
        """
        Convert the HTTP conversation to HTTP Archive (HAR) format.
        :return: the HTTP conversation (request and response) in HAR format
        """
        return {
            'startedDateTime': self.request.started_date,
            'timestamp': self.request_timestamp,
            'time': 0,  # TODO?
            'timings': {
                'send': self.request.sending_duration,
                'wait': self.waiting_duration,
                'receive': self.response.receiving_duration
            },
            'cache': {},
            'request': self.request.to_har(),
            'response': self.response.to_har()
        }


class HttpTraffic:
    """
    Class to represent HTTP network traffic. This class is the entry point for parsing HTTP network traffic.

    The format of JSON data from tshark is as follows for a single HTTP request:
    - `GET /spi/v2/platforms/ HTTP/1.1\\r\\n`: Contains the HTTP method, URI, and version.
    - `http.request.version`: The HTTP version used.
    - `http.request.line`: A list of HTTP headers sent with the request.
    - `http.host`: The Host header value.
    - `http.request.full_uri`: The full URI including the scheme (e.g., https).
    - `http.request_number`: The request number.
    - `http.response_in`: The response number associated with this request.

    The format of JSON data from tshark is as follows for a single HTTP response:
    - `HTTP/1.1 200 OK\\r\\n`: Contains the HTTP version, status code, and status phrase.
    - `http.content_type`: The Content-Type header value.
    - `http.response.line`: A list of HTTP headers sent with the response.
    - `http.content_encoding`: The Content-Encoding header value.
    - `http.response_number`: The response number.
    - `http.time`: The time taken for the response.
    - `http.request_in`: The request number associated with this response.
    - `http.response_for.uri`: The URI for which this response is generated.
    - `http.file_data_raw`: The data in hexadecimal format (requires -x flag).
    """
    def __init__(self, traffic: Sequence[DictLayers]):
        self.traffic = traffic
        self.conversations: list[HttpConversation] = []
        self.parse_traffic()

    def parse_traffic(self) -> None:
        """
        Parse the HTTP network traffic and extract the request-response pairs.

        Identify each HTTP request and its associated HTTP response by following these steps:
        1. Iterate through packets: It loops through all packets obtained from the `traffic` object.
        2. Check protocols: It checks if the packet contains the `http` protocol by examining the `frame.protocols`
           field.
        3. Identify http requests: It checks if the packet contains an HTTP request by looking for the `http.request`
           key in the `http` layer.
        4. Find associated response: If the packet is an HTTP request and contains the `http.response_in` key, it
           retrieves the corresponding response packet using the `get_packet_by_number` method with the response number.
        5. Create conversation: It creates an `HttpConversation` object with the request and response packets and
           appends it to the `conversations` list.
        """
        layers_mapping = get_layers_mapping(self.traffic)

        for request_layers in self.traffic:
            protocols = request_layers['frame']['frame.protocols'].split(':')
            if 'http' not in protocols:
                continue
            http_layer = request_layers['http']
            if 'http.request' not in http_layer or 'http.response_in' not in http_layer:
                continue
            # This is a request
            response_layers = layers_mapping[int(http_layer['http.response_in'])]
            self.conversations.append(HttpConversation(request_layers, response_layers))

    def get_har_entries(self) -> list[dict[str, Any]]:
        """
        Convert the HTTP network traffic to HTTP Archive (HAR) format.
        :return: the HTTP network traffic in HAR format
        """
        entries = []
        for http_conversation in self.conversations:
            entries.append(http_conversation.to_har())
        return entries
