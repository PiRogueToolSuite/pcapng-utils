import logging
from http import HTTPMethod
from abc import ABC, abstractmethod
from functools import cached_property
from dataclasses import dataclass
from collections import defaultdict
from collections.abc import Sequence
from typing import ClassVar, Any

from ...payload import Payload
from ..layers import FrameMixin, TCPIPMixin, CommunityIDMixin, get_protocols, get_layers_mapping, get_har_communication
from ..types import HarEntry, DictLayers
from ..utils import get_tshark_bytes_from_raw, har_entry_with_common_fields
from .websocket import WebSocketConversation, WebSocketFrames, is_websocket_conversation


LOGGER = logging.getLogger(__name__)

HTTP_METHODS = {str(v) for v in HTTPMethod}


def _get_raw_headers(http_layer: dict[str, Any], direction: str) -> list[bytes]:
    raw_headers = http_layer.get(f"http.{direction}.line_raw")
    if not raw_headers:
        return []
    if isinstance(http_layer[f"http.{direction}.line"], str):  # only 1 header (dirty structure)
        raw_headers = [raw_headers]
    return [get_tshark_bytes_from_raw(h) for h in raw_headers]


@dataclass(frozen=True)
class HttpRequestResponse(ABC, FrameMixin, TCPIPMixin, CommunityIDMixin):
    """
    Base class for HTTP request and response packets. It wraps the layers data and provides methods to
    access the relevant information.
    """
    layers: DictLayers

    FALLBACK_CONTENT_TYPE: ClassVar[str] = 'application/octet-stream'

    @property
    def http_layer(self) -> dict[str, Any]:
        return self.layers['http']

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
            'cookies': [],  # TODO?
            'headers': self.headers,
            'headersSize': self.header_length,
            'bodySize': self.content_length,
            '_timestamp': self.timestamp,
            '_rawFramesNumbers': [self.frame_nb],  # always 1 frame in HTTP1
            '_communication': get_har_communication(self),
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
        return round(1000 * float(self.layers['frame'].get('frame.time_delta', 0)), 2)

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

    If this HTTP conversation is a websocket handshake then it shall also contain the websocket conversation.
    """
    def __init__(self, request: HttpRequest, response: HttpResponse):
        self.request = request
        self.response = response
        self.websocket_conversation = (
            WebSocketConversation(request.src_dst_ip_port)
            if is_websocket_conversation(
                request.http_layer,
                response.http_layer,
                response_code=response.http_version_status_code_message[1],
            )
            else None
        )

    @property
    def tcp_stream_id(self) -> int:
        sid = self.request.tcp_stream_id
        try:
            assert sid == self.response.tcp_stream_id, (sid, self.response.tcp_stream_id)
        except KeyError:  # buggy/incomplete response may not have `tcp_stream` but OK
            pass
        return sid

    @property
    def community_id(self) -> str:
        cid = self.request.community_id
        try:
            assert cid == self.response.community_id, (cid, self.response.community_id)
        except KeyError:  # buggy/incomplete response may not have `community_id` but OK
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
            'response': self.response.to_har(),
            **(
                self.websocket_conversation.to_har()
                if self.websocket_conversation is not None
                else {}
            ),
        })


DELTA_MS_ORPHANS_AFTER_PENALTY = 50.0
DELTA_MS_ORPHANS_WINDOW_WARN = (-250.0, 50.0)
DELTA_MS_ORPHANS_WINDOW_IGNORE = (-2500.0, 500.0)


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
        3.a. If traffic correspond to websocket, try to bind it to the originating HTTP conversation
        3.b. Otherwise, we identify http requests by checking if the packet contains the `http.request`.
        4. Find associated response: If the packet is an HTTP request and contains the `http.response_in` key, it
           retrieves the corresponding response packet using response number and the `layers_mapping`, otherwise
           it will handle it later with orphan responses logic.
        5. Create conversation: It creates an `HttpConversation` object with the request and response packets and
           appends it to the `conversations` list.
        """
        layers_mapping = get_layers_mapping(
            # discard non-http traffic
            [layers for layers in self.traffic if 'http' in get_protocols(layers)]
        )
        websocket_conversations_per_tcp_stream_id = defaultdict[int, list[WebSocketConversation]](list)
        orphan_requests_per_tcp_stream = defaultdict[int, list[HttpRequest]](list)
        response_nb_blacklist = set[int]()

        for layers in layers_mapping.values():
            if 'websocket' in layers:
                ws_frames = WebSocketFrames(layers)
                ws_convs = websocket_conversations_per_tcp_stream_id[ws_frames.tcp_stream_id]
                assert ws_convs, (ws_frames.tcp_stream_id, ws_frames)
                ws_convs[-1].push(ws_frames)
                continue
            if 'http' not in layers:
                # happens that both 'http' & 'http2' are in `protocols` but only 'http2' in actual layers
                continue
            # we only retain HTTP requests from now on
            request_http_layer = layers['http']
            if 'http.request' not in request_http_layer:
                continue
            request = HttpRequest(layers)
            if 'http.response_in' not in request_http_layer:
                orphan_requests_per_tcp_stream[request.tcp_stream_id].append(request)
                continue
            response_nb = int(request_http_layer['http.response_in'])
            assert response_nb not in response_nb_blacklist, (request.frame_nb, response_nb)
            response_nb_blacklist.add(response_nb)
            http_conversation = HttpConversation(request, HttpResponse(layers_mapping[response_nb]))
            self.conversations.append(http_conversation)
            # handle websocket conversations if needed
            if http_conversation.websocket_conversation is not None:
                ws_convs_for_cur_tcp_stream = websocket_conversations_per_tcp_stream_id[http_conversation.tcp_stream_id]
                open_ws_convs_for_cur_tcp_stream = [ws_conv for ws_conv in ws_convs_for_cur_tcp_stream if not ws_conv.is_closed]
                if open_ws_convs_for_cur_tcp_stream:
                    raise NotImplementedError(
                        "There are still some opened WebSocket conversations "
                        f"for TCP stream #{http_conversation.tcp_stream_id}: {open_ws_convs_for_cur_tcp_stream}"
                    )
                ws_convs_for_cur_tcp_stream.append(http_conversation.websocket_conversation)

        # try to match orphan responses with orphan requests (esp. for '206 Partial content' responses)
        for response_nb, response_layers in layers_mapping.items():
            response_http_layer = response_layers.get('http')
            if response_nb in response_nb_blacklist or not (response_http_layer and 'http.response' in response_http_layer):
                continue
            response = HttpResponse(response_layers)
            existing_orphan_requests = orphan_requests_per_tcp_stream.get(response.tcp_stream_id, [])
            possible_requests = sorted([
                (req_ix, req.frame_nb, delta_ms)
                for req_ix, req in enumerate(existing_orphan_requests)
                if DELTA_MS_ORPHANS_WINDOW_IGNORE[0] < (delta_ms := (req.timestamp - response.timestamp) * 1000) < DELTA_MS_ORPHANS_WINDOW_IGNORE[1]
            ], key=lambda tup: abs(tup[-1]) + DELTA_MS_ORPHANS_AFTER_PENALTY*(0 if tup[-1] <= 0 else 1))
            _, resp_status_code, _ = response.http_version_status_code_message
            resp_lbl = f"HTTP1 response (Frame #{response_nb}, TCP stream #{response.tcp_stream_id}, Code {resp_status_code})"
            if not possible_requests:
                # TODO? totally skip pairing for 1xx responses?
                (LOGGER.info if resp_status_code in {100, 102} else LOGGER.warning)(
                    f"Orphan {resp_lbl} did not match with any orphan HTTP1 request"
                )
                continue
            if len(possible_requests) > 1:
                LOGGER.debug(
                    f"Ambiguous matching of orphan {resp_lbl} with possible orphan requests {[f'#{req_nb}' for _, req_nb, _ in possible_requests]}"
                )
            req_ix, req_nb, delta_ms = possible_requests[0]  # first is best (sorted)
            request = existing_orphan_requests.pop(req_ix)  # this request is not orphan anymore
            if not (DELTA_MS_ORPHANS_WINDOW_WARN[0] < delta_ms < DELTA_MS_ORPHANS_WINDOW_WARN[1]):
                LOGGER.warning(f"Dubious matching of orphan {resp_lbl} with orphan request #{req_nb}")

            http_conv = HttpConversation(request, response)
            self.conversations.append(http_conv)

        # log any orphan requests remaining
        for tcp_stream_id, orphan_requests_for_tcp_stream in orphan_requests_per_tcp_stream.items():
            if orphan_requests_for_tcp_stream:
                reqs_lbls = [
                    f"Frame #{req.frame_nb}: {' '.join(req.http_version_method)} {req.uri}"
                    for req in orphan_requests_for_tcp_stream
                ]
                LOGGER.warning(
                    f"TCP stream #{tcp_stream_id}: some orphan HTTP1 requests remain: {reqs_lbls}"
                )

    def get_har_entries(self) -> list[HarEntry]:
        """
        Convert the HTTP network traffic to HTTP Archive (HAR) format.
        :return: the HTTP network traffic in HAR format
        """
        entries = []
        for http_conversation in self.conversations:
            entries.append(http_conversation.to_har())
        return entries
