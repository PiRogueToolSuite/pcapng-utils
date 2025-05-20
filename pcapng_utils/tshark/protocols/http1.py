from abc import ABC, abstractmethod
from functools import cached_property
from dataclasses import dataclass
from collections.abc import Sequence
from typing import ClassVar, Any

from ...payload import Payload
from ..types import HarEntry, DictLayers
from ..utils import get_layers_mapping, get_tshark_bytes_from_raw, har_entry_with_common_fields

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

    FALLBACK_CONTENT_TYPE: ClassVar[str] = 'application/octet-stream'

    @property
    def frame_nb(self) -> int:
        # useful for debugging with Wireshark
        return int(self.packet['frame']['frame.number'])

    @property
    def community_id(self) -> str:
        return self.packet['communityid']

    @cached_property
    def ip_version_and_layer(self) -> tuple[str, dict[str, Any]]:
        ipv4 = "ip" in self.packet
        ipv6 = "ipv6" in self.packet
        assert ipv4 ^ ipv6, self
        ip_version_kw = "ipv6" if ipv6 else "ip"
        return ip_version_kw, self.packet[ip_version_kw]

    @property
    def src_host(self) -> str:
        ipv, ip_layer = self.ip_version_and_layer
        return ip_layer[f"{ipv}.src_host"]

    @property
    def dst_host(self) -> str:
        ipv, ip_layer = self.ip_version_and_layer
        return ip_layer[f"{ipv}.dst_host"]

    @property
    def src_ip(self) -> str:
        ipv, ip_layer = self.ip_version_and_layer
        return ip_layer[f"{ipv}.src"]

    @property
    def dst_ip(self) -> str:
        ipv, ip_layer = self.ip_version_and_layer
        return ip_layer[f"{ipv}.dst"]

    @property
    def src_port(self) -> int:
        return int(self.packet['tcp']['tcp.srcport'])

    @property
    def dst_port(self) -> int:
        return int(self.packet['tcp']['tcp.dstport'])

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
        content_type: str | list[str] = self.http_layer.get('http.content_type', self.FALLBACK_CONTENT_TYPE)
        if isinstance(content_type, list):
            content_type = content_type[-1]  # we take last value when multiple values
        return content_type

    @cached_property
    def payload(self) -> Payload:
        raw_data = self.http_layer.get('http.file_data_raw')
        if raw_data is None:
            # handle tshark error during decompression
            for k, v in self.http_layer.items():
                if k.lower().startswith('content-encoded entity body ') and isinstance(v, dict):
                    raw_data = v['data_raw']
                    break
        return Payload(get_tshark_bytes_from_raw(raw_data))

    @property
    def content_length(self) -> int:
        return self.payload.size

    @property
    def timestamp(self) -> float:
        return float(self.packet['frame']['frame.time_epoch'])

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

    @property
    def common_har_props(self) -> dict[str, Any]:
        return {
            'cookies': [],
            'headers': self.headers,
            'headersSize': self.header_length,
            'bodySize': self.content_length,
            '_timestamp': self.timestamp,
            '_rawFramesNumbers': [self.frame_nb],  # always 1 frame in HTTP1
            '_communication': {
                'src': {
                    'ip': self.src_ip,
                    'host': self.src_host,
                    'port': self.src_port,
                },
                'dst': {
                    'ip': self.dst_ip,
                    'host': self.dst_host,
                    'port': self.dst_port,
                }
            },
        }


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
            'method': method,
            'url': self.uri,
            'queryString': [],
            'httpVersion': http_version,
            **self.common_har_props,
        }
        if self.content_length:
            self.payload.update_har_request(d, self.content_type)
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
        d = {
            'status': status_code,
            'statusText': status_message,
            'redirectURL': '',
            'httpVersion': http_version,
            **self.common_har_props,
        }
        self.payload.update_har_response(d, self.content_type)
        return d

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
        try:
            assert cid == self.response.community_id, (cid, self.response.community_id)
        except KeyError: # buggy/incomplete response may not have `community_id` but OK
            pass
        return cid

    @property
    def waiting_duration(self) -> float:
        return round(1000 * (self.response.timestamp - self.request.timestamp), 2)

    def to_har(self) -> dict[str, Any]:
        """
        Convert the HTTP conversation to HTTP Archive (HAR) format.
        :return: the HTTP conversation (request and response) in HAR format
        """
        return har_entry_with_common_fields({
            '_timestamp': self.request.timestamp,
            'timings': {
                'send': self.request.sending_duration,
                'wait': self.waiting_duration,
                'receive': self.response.receiving_duration
            },
            'serverIPAddress': self.request.dst_ip,
            '_communityId': self.community_id,
            'request': self.request.to_har(),
            'response': self.response.to_har()
        })


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
