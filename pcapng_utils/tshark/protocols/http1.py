from abc import ABC, abstractmethod
from datetime import datetime, timezone
from functools import cached_property
from dataclasses import dataclass
from typing import Sequence, ClassVar, Any

from ..types import HarEntry, DictLayers
from ..utils import Payload, get_layers_mapping, get_tshark_bytes_from_raw

HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'}


def _get_raw_headers(http_layer: dict[str, Any], direction: str) -> list[bytes]:
    raw_headers = http_layer.get(f"http.{direction}.line_raw")
    if not raw_headers:
        return []
    if isinstance(http_layer[f"http.{direction}.line"], str):  # only 1 header (dirty structure)
        raw_headers = [raw_headers]
    return [get_tshark_bytes_from_raw(h) for h in raw_headers]


@dataclass(frozen=True)
class HttpRequestResponse(ABC):
    """
    Base class for HTTP request and response packets. It wraps the packet data and provides methods to
    access the relevant information.
    """
    packet: DictLayers

    FALLBACK_CONTENT_TYPE: ClassVar = 'application/octet-stream'

    @property
    def community_id(self) -> str:
        return self.packet['communityid']

    @property
    def src_host(self) -> str:
        return self.packet['ip'].get('ip.src_host', '')

    @property
    def dst_host(self) -> str:
        return self.packet['ip'].get('ip.dst_host', '')

    @property
    def src_ip(self) -> str:
        return self.packet['ip']['ip.src']

    @property
    def dst_ip(self) -> str:
        return self.packet['ip']['ip.dst']

    @property
    def http_layer(self) -> dict[str, Any]:
        return self.packet['http']

    @property
    @abstractmethod
    def raw_headers(self) -> Sequence[bytes]:
        pass

    @property
    def header_length(self) -> int:
        return len(b''.join(self.raw_headers))

    @property
    def content_type(self) -> str:
        if not self.payload:
            return ''
        return self.http_layer.get('http.content_type', self.FALLBACK_CONTENT_TYPE)

    @cached_property
    def payload(self) -> Payload:
        raw_data = self.http_layer.get('http.file_data_raw')
        if raw_data is None:
            # handle tshark error during decompression
            for k, v in self.http_layer.items():
                if k.lower().startswith('content-encoded entity body ') and isinstance(v, dict):
                    raw_data = v['data_raw']
                    break
        return Payload.from_tshark_raw(raw_data)

    @property
    def content_length(self) -> int:
        return self.payload.size

    @property
    def timestamp(self) -> float:
        return float(self.packet['frame']['frame.time_epoch'])

    @property
    def started_date(self) -> str:
        frame_time: str = self.packet['frame']['frame.time_epoch']
        return datetime.fromtimestamp(float(frame_time), timezone.utc).isoformat()

    @cached_property
    def headers(self) -> list[dict[str, str]]:
        assert isinstance(self.raw_headers, list), self.raw_headers
        processed_headers = []
        for header in self.raw_headers:
            key_value = header.decode().split(':', 1)  # on rare occasions there is no space after colon
            assert len(key_value) == 2, key_value
            key, value = key_value
            processed_headers.append({
                'name': key.strip(),
                'value': value.strip(),
            })
        return processed_headers


@dataclass(frozen=True)
class HttpRequest(HttpRequestResponse):
    """
    Class to represent an HTTP request.
    """
    @property
    def raw_headers(self) -> list[bytes]:
        return _get_raw_headers(self.http_layer, 'request')

    @cached_property
    def http_version_method(self) -> tuple[str, str]:
        """
        Get the HTTP version & method from the packet data.
        :return: tuple with HTTP version & method
        """
        for d in self.http_layer.values():
            if not isinstance(d, dict) or 'http.request.version' not in d:
                continue
            version = d['http.request.version']
            assert version.startswith('HTTP/1.'), version
            meth = d['http.request.method']
            assert meth in HTTP_METHODS, meth
            return version, meth
        return 'HTTP/1.1', ''

    @property
    def sending_duration(self) -> float:
        return round(1000 * float(self.packet['frame'].get('frame.time_delta', 0)), 2)

    def to_har(self) -> dict[str, Any]:
        """
        Convert the HTTP request to HTTP Archive (HAR) format.
        :return: the HTTP request in HAR format
        """
        http_version, method = self.http_version_method
        d = {
            'startedDateTime': self.started_date,
            'method': method,
            'url': self.uri,
            'httpVersion': http_version,
            'headers': self.headers,
            'queryString': [],
            'cookies': [],
            '_timestamp': self.timestamp,
            '_communication': {
                'src': {
                    'ip': self.src_ip,
                    'host': self.src_host,
                },
                'dst': {
                    'ip': self.dst_ip,
                    'host': self.dst_host,
                }
            },
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
        return self.http_layer['http.request.full_uri']


@dataclass(frozen=True)
class HttpResponse(HttpRequestResponse):
    """
    Class to represent an HTTP response.
    """
    @property
    def raw_headers(self) -> list[bytes]:
        return _get_raw_headers(self.http_layer, 'response')

    @cached_property
    def http_version_status_code_message(self) -> tuple[str, int, str]:
        """
        Retrieve the HTTP version & status code & message.
        :return: tuple with HTTP version, status code and message
        """
        for d in self.http_layer.values():
            if not isinstance(d, dict) or 'http.response.version' not in d:
                continue
            version = d['http.response.version']
            assert version.startswith('HTTP/1.'), version
            return version, int(d['http.response.code']), d['http.response.code.desc']
        return 'HTTP/1.1', 0, ''

    def to_har(self):
        """
        Convert the HTTP response to HTTP Archive (HAR) format.
        :return: the HTTP response in HAR format
        """
        http_version, status_code, status_message = self.http_version_status_code_message
        return {
            'startedDateTime': self.started_date,
            'status': status_code,
            'statusText': status_message,
            'redirectURL': '',
            'httpVersion': http_version,
            'headers': self.headers,
            'cookies': [],
            'headersSize': self.header_length,
            'bodySize': self.content_length,
            '_timestamp': self.timestamp,
            '_communication': {
                'src': {
                    'ip': self.src_ip,
                    'host': self.src_host,
                },
                'dst': {
                    'ip': self.dst_ip,
                    'host': self.dst_host,
                }
            },
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
    def community_id(self) -> str:
        cid = self.request.community_id
        assert cid == self.response.community_id, (cid, self.response.community_id)
        return cid

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
            'time': self.request.sending_duration + self.waiting_duration + self.response.receiving_duration,
            'timings': {
                'send': self.request.sending_duration,
                'wait': self.waiting_duration,
                'receive': self.response.receiving_duration
            },
            'cache': {},
            'serverIPAddress': self.request.dst_ip,
            '_communityId': self.community_id,
            'request': self.request.to_har(),
            'response': self.response.to_har()
        }


class Http1Traffic:
    """
    Class to represent HTTP1 network traffic.

    This class is the entry point for parsing HTTP1 network traffic.

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
            if 'http' not in protocols or 'http' not in request_layers:
                # happens that both 'http' & 'http2' are in `protocols`
                # but only 'http2' is in layers
                continue
            http_layer = request_layers['http']
            if 'http.request' not in http_layer or 'http.response_in' not in http_layer:
                continue
            # This is a request
            response_layers = layers_mapping[int(http_layer['http.response_in'])]
            self.conversations.append(HttpConversation(request_layers, response_layers))

    def get_har_entries(self) -> list[HarEntry]:
        """
        Convert the HTTP network traffic to HTTP Archive (HAR) format.
        :return: the HTTP network traffic in HAR format
        """
        entries = []
        for http_conversation in self.conversations:
            entries.append(http_conversation.to_har())
        return entries
