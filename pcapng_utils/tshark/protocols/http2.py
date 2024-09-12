import warnings
from datetime import datetime
from functools import cached_property
from typing import Sequence, ClassVar, Optional, Any

import pytz

from ..types import HarEntry, DictLayers, NameValueDict
from ..utils import Payload, get_tshark_bytes_from_raw


class Http2Substream:
    """
    Class to represent a HTTP2 substream. It contains the layers of the packet and the metadata of the substream.
    Wrap the raw HTTP2 substream and the frame layers to extract the relevant information.
    """
    KEEP_LAYERS: ClassVar = {'ip', 'frame'}

    def __init__(self, raw_http2_substream: dict[str, Any], all_layers: DictLayers):
        self.packet_layers: dict[str, Any] = {}
        for layer, data in all_layers.items():
            if layer in self.KEEP_LAYERS:
                self.packet_layers[layer] = data
        self.raw_http2_substream = raw_http2_substream

    @property
    def http2_flags(self) -> int:
        return int(self.raw_http2_substream.get('http2.flags', '0x0'), 0)

    @property
    def http2_type(self) -> int:
        return int(self.raw_http2_substream.get('http2.type', -1))

    @property
    def ip_layer(self) -> dict[str, Any]:
        return self.packet_layers['ip']

    @property
    def frame_layer(self) -> dict[str, Any]:
        return self.packet_layers['frame']

    @property
    def src_host(self) -> str:
        return self.ip_layer.get('ip.src_host', '')

    @property
    def dst_host(self) -> str:
        return self.ip_layer.get('ip.dst_host', '')

    @property
    def src_ip(self) -> str:
        return self.ip_layer['ip.src']

    @property
    def dst_ip(self) -> str:
        return self.ip_layer['ip.dst']

    @property
    def raw_headers(self) -> list[dict[str, Any]]:
        return self.raw_http2_substream.get('http2.header', [])

    @property
    def started_date(self) -> str:
        frame_time: str = self.frame_layer['frame.time_epoch']
        return datetime.fromtimestamp(float(frame_time), pytz.utc).isoformat()

    def get_time_s(self) -> float:
        return float(self.frame_layer.get('frame.time_epoch', 0))


class Http2RequestResponse:
    """
    Base class to represent a HTTP2 request or response. It contains the headers and data of the request or response.
    Implements the common properties of a HTTP2 request or response.
    """
    FALLBACK_CONTENT_TYPE: ClassVar = 'application/octet-stream'

    def __init__(self, substreams: list[Http2Substream]):
        self.substreams = substreams
        self.headers, self.data, self.headers_streams, self.data_streams = Http2Helper.get_headers_and_data(substreams)

    def __bool__(self) -> bool:
        return bool(self.substreams)

    @property
    def http_version(self) -> str:
        return 'HTTP/2'

    @property
    def header_length(self) -> int:
        # The effective payload sent over network has bytes size `http2.length` <= `http2.headers.length`
        # (because special headers - like `:status` - have predefined codes)
        if not self:
            return -1
        return sum(int(s.raw_http2_substream.get('http2.length', 0)) for s in self.headers_streams)

    @property
    def body_length(self) -> int:
        """
        <!> In Tshark < 4.2.0:
        - we do not have `http2.body.*`
        - `http2.length` is also populated for header substreams
        """
        if not self:
            return -1
        declared_size = sum(int(s.raw_http2_substream.get('http2.length', 0)) for s in self.data_streams)
        if declared_size != self.data.size and not self.headers_map.get('content-encoding', ''):
            warnings.warn(
                f"Content length mismatch despite no compression: "
                f"declared ({declared_size}) != computed ({self.data.size})"
                f"\n{self}"
            )
        return declared_size

    @cached_property
    def headers_map(self) -> dict[str, str]:
        return {
            h['name'].lower(): h['value']
            for h in self.headers
        }

    @property
    def http_status(self) -> int:
        return int(self.headers_map.get(':status', 0))

    @property
    def http_method(self) -> str:
        return self.headers_map.get(':method', '')

    @property
    def content_type(self) -> str:
        if not self or not self.data:
            return ''
        return self.headers_map.get('content-type', self.FALLBACK_CONTENT_TYPE)

    def get_duration_ms(self) -> float:
        if not self:
            return -1
        return round(1000 * (self.substreams[-1].get_time_s() - self.substreams[0].get_time_s()), 2)


class Http2Request(Http2RequestResponse):
    """
    Class to represent a HTTP2 request. It contains the headers and data of the request.
    """
    def __init__(self, substreams: list[Http2Substream]):
        assert substreams, "At least one substream expected for a request"
        super().__init__(substreams)

    @property
    def uri(self) -> str:
        uris = {s.raw_http2_substream['http2.request.full_uri'] for s in self.headers_streams}
        assert len(uris) == 1, uris
        return next(iter(uris))

    def __str__(self):
        return f'Request - {len(self.substreams)} substreams\n\tURI: {self.uri}\n\tHeaders: {self.headers}\n\tData: {self.data}'


class Http2Response(Http2RequestResponse):
    """
    Class to represent a HTTP2 response. It contains the headers and data of the response.

    <!> May be empty for convenience (response never received)
    """
    def __str__(self):
        return f'Response - {len(self.substreams)} substreams\n\tHeaders: {self.headers}\n\tData: {self.data}'


class Http2Stream:
    """
    Class to represent an entire HTTP2 stream (multiple substreams). It contains the request and response objects.
    Http2Stream represents a single HTTP2 stream that can contain multiple substreams as follows:
     +-------------------------------------- (tcp stream, http2 stream)
     | Http2SubStream 1    | Request headers (type: 1)
     | Http2SubStream ...  | Request data (type: 0, flags: 0x0) - partial data
     | Http2SubStream 3    | Request data (type: 0, flags: 0x1) - end of stream, contains reassembled data
     | (Http2SubStream 4   | Request trailers (type: 1))
     +--------------------------------------
     | Http2SubStream 5    | Response headers (type: 1)
     | Http2SubStream ...  | Response data (type: 0, flags: 0x0) - partial data
     | Http2SubStream 7    | Response data (type: 0, flags: 0x1) - end of stream, contains reassembled data
     | (Http2SubStream 8   | Response trailers (type: 1))
     +--------------------------------------
     Each HTTP2 steam is defined by a tuple (tcp stream, http2 stream) and contains both request and response objects.
    """
    def __init__(self, tcp_stream_id: int, http2_stream_id: int):
        """
        Defines a HTTP2 stream for the given TCP stream and HTTP2 stream.

        :param tcp_stream_id: the ID of the TCP stream
        :param http2_stream_id: the ID of the HTTP2 stream
        """
        self.tcp_stream_id = tcp_stream_id
        self.http2_stream_id = http2_stream_id
        self.request: Optional[Http2Request] = None
        self.response: Optional[Http2Response] = None
        self.substreams: list[Http2Substream] = []

    @property
    def id(self) -> tuple[int, int]:
        return (self.tcp_stream_id, self.http2_stream_id)

    def append(self, raw_http2_substream: dict[str, Any], all_layers: DictLayers) -> None:
        """
        Append a new substream to the HTTP2 stream.

        :param substream: the substream to be added
        :param frame: the frame containing the substream. A frame can contain multiple substreams.
        """
        self.substreams.append(Http2Substream(raw_http2_substream, all_layers))

    @property
    def waiting_duration(self) -> float:
        if not self.response:
            return 0
        assert self.request, self.id
        start_stream = self.request.substreams[-1]
        resp_stream = self.response.substreams[0]
        return round(1000 * (resp_stream.get_time_s() - start_stream.get_time_s()), 2)

    def har_entry(self) -> Optional[dict[str, Any]]:
        """
        Create a HAR entry for the HTTP2 stream. It contains the request and response objects.

        :return: the HAR entry for the HTTP2 stream
        """
        assert self.request is not None, self.id
        assert self.response is not None, self.id
        if not self.request:
            assert not self.response, self.id
            return None
        first_stream = self.request.headers_streams[0]
        return {
            'startedDateTime': first_stream.started_date,
            'timestamp': first_stream.get_time_s(),
            'time': 0,  # not used
            'timings': {
                'send': self.request.get_duration_ms(),
                'wait': self.waiting_duration,
                'receive': self.response.get_duration_ms(),
            },
            'cache': {},
            'request': Http2Helper.to_har(self.request),
            'response': Http2Helper.to_har(self.response),
        }

    @staticmethod
    def get_raw_data(raw_http2_substream: dict[str, Any]) -> Payload:
        """
        Find the data in the substream.

        :param substream: the substream to be analyzed
        :return: the raw reassembled data (in hex format) if it exists, otherwise an empty string

        <!> http2.body.fragments -> http2.body.reassembled.data not available in tshark < 4.2.0
        """
        for k, v in raw_http2_substream.items():
            if k.lower().startswith('content-encoded') and 'http2.data.data_raw' in v:
                return Payload.from_tshark_raw(v['http2.data.data_raw'])
        return Payload.from_tshark_raw(raw_http2_substream.get('http2.data.data_raw'))

    def process(self) -> None:
        """
        Process the substreams and create the request and response objects accordingly. Substreams are processed in
        order, the first substreams are request headers, followed by request data, and finally the response headers and
        data. The reassembled data is used to create the request and response objects.

        Request substreams are identified by the presence of the 'http2.request.full_uri' key in the raw stream.
        If no response substream is found, the request object is created with the first substreams.

        It retrieves the source and destination IP addresses from the first substream to identify the substreams that
        belong to the request. The response substreams are identified by checking their source IP address matches
        the destination IP address of the first substream.
        """
        assert self.substreams, self.id

        # Find a request frame and its associated IPs
        src, dst = None, None
        for substream in self.substreams:
            if 'http2.request.full_uri' in substream.raw_http2_substream:  # This is a request
                src, dst = substream.src_ip, substream.dst_ip
                break
        assert src and dst, self.substreams
        assert src != dst, src

        # Create the request and response objects with their associated substreams
        req_substreams = [substream for substream in self.substreams if substream.src_ip == src]
        resp_substreams = [substream for substream in self.substreams if substream.src_ip == dst]
        assert len(req_substreams) + len(resp_substreams) == len(self.substreams), self.substreams
        self.request = Http2Request(req_substreams)
        self.response = Http2Response(resp_substreams)  # may be empty

    def __str__(self):
        return (
            f'TCP Stream: {self.tcp_stream_id}, '
            f'HTTP2 Stream: {self.http2_stream_id}'
            f'\n{self.request}'
            f'\n{self.response}'
        )


class Http2Helper:

    @staticmethod
    def substream_is_header(substream: Http2Substream) -> bool:
        """Returns whether substream is a header substream."""
        stream_type = substream.http2_type
        return stream_type == 1

    @staticmethod
    def substream_is_data(substream: Http2Substream) -> bool:
        """Returns whether substream is a data substream."""
        stream_type = substream.http2_type
        return stream_type == 0

    @staticmethod
    def get_headers(substream: Http2Substream) -> list[NameValueDict]:
        """
        Extract the headers from the substream (precondition: it is a header substream).

        :param substream: the substream to be analyzed
        :return: the headers of the substream
        """
        headers: list[NameValueDict] = []
        for header in substream.raw_headers:
            # cope for non-ASCII headers
            h_name = get_tshark_bytes_from_raw(header['http2.header.name_raw']).decode()
            h_value = get_tshark_bytes_from_raw(header.get('http2.header.value_raw')).decode()
            headers.append({
                'name': h_name.strip(),
                'value': h_value.strip(),
            })
        return headers

    @staticmethod
    def to_har(message: Http2RequestResponse) -> dict[str, Any]:
        """
        Convert the HTTP2 request or response to a HAR entry.

        :param message: the HTTP2 request or response to be converted
        :return: the HAR entry for the HTTP2 request or response
        """
        entry = {
            'httpVersion': message.http_version,
            'headers': message.headers,
            'queryString': [],  # TODO?
            'cookies': [],  # TODO?
            'headersSize': message.header_length,
            'bodySize': message.body_length,
        }
        if isinstance(message, Http2Request):
            entry['method'] = message.http_method
            entry['url'] = message.uri
            if message.data.size:
                entry['postData'] = {
                    'mimeType': message.content_type,
                    **message.data.to_har_dict(),
                    'params': [],  # TODO?
                }
        else:
            entry['status'] = message.http_status
            entry['statusText'] = ''
            entry['redirectURL'] = ''
            entry['content'] = {
                'mimeType': message.content_type,
                **message.data.to_har_dict(),
            }
        return entry

    @staticmethod
    def get_data(substream: Http2Substream) -> Payload:
        """
        Extract the data from the substream (precondition: the substream is a data substream).

        :param substream: the substream to be analyzed
        :return: the reassembled data if it is a data substream, otherwise None
        """
        return Http2Stream.get_raw_data(substream.raw_http2_substream)

    @classmethod
    def get_headers_and_data(cls, substreams: list[Http2Substream]):
        """
        Identify the headers and data substreams and return them.

        The substreams are identified by their types:
        - Headers substream: type 1
        - Data substream: type 0
        We ignore the rest of the substreams.

        Note that (flag & 0x01) identify the end of stream, usually it happens for a data-stream
        but it may also happen for a header-stream (trailers in gRPC).

        :param substreams: the substreams of a HTTP2 stream
        :return: the headers and data substreams regardless if it is a request or a response
        """
        headers: list[NameValueDict] = []
        datas: list[Payload] = []
        headers_streams: list[Http2Substream] = []
        data_streams: list[Http2Substream] = []

        for substream in substreams:
            # Parse headers (HTTP2 substream marked as headers)
            if cls.substream_is_header(substream):
                headers_streams.append(substream)
                headers += Http2Helper.get_headers(substream)
            # Parse data (HTTP2 substream marked as data and flagged end of stream)
            if cls.substream_is_data(substream):
                data_streams.append(substream)
                datas.append(Http2Helper.get_data(substream))

        if substreams:
            assert headers_streams, (len(substreams), data_streams)

        return headers, Payload.concat(*datas), headers_streams, data_streams


class Http2Traffic:
    """
    Class to represent the HTTP2 traffic. It contains the HTTP2 streams and the parsed traffic data.

    In HTTP/2, frames are the smallest unit of communication.
    Each frame has a specific type and can have associated flags.

        **HTTP/2 frame types and flags:**
        HTTP/2 Frame Types:
        - `DATA (0x0)`: carries arbitrary, variable-length sequences of octets associated with a stream.
        - `HEADERS (0x1)`: used to open a stream and carry a header block fragment.
        - `PRIORITY (0x2)`: specifies the sender-advised priority of a stream.
        - `RST_STREAM (0x3)`: abruptly terminates a stream.
        - `SETTINGS (0x4)`: used to communicate configuration parameters.
        - `PUSH_PROMISE (0x5)`: used to notify the peer endpoint in advance of streams the sender intends to initiate.
        - `PING (0x6)`: used to measure round-trip time and ensure the connection is still active.
        - `GOAWAY (0x7)`: informs the peer to stop creating streams on this connection.
        - `WINDOW_UPDATE (0x8)`: used to implement flow control.
        - `CONTINUATION (0x9)`: used to continue a sequence of header block fragments.

        HTTP/2 Frame Flags:
        - `END_STREAM (0x1)`: indicates that the frame is the last one for the current stream.
        - `END_HEADERS (0x4)`: indicates that the frame contains the entire header block.
        - `PADDED (0x8)`: indicates that the frame contains padding.
        - `PRIORITY (0x20)`: indicates that the frame contains priority information.

        **TCP stream ID and the HTTP/2 stream ID:**
        The TCP stream ID identifies a unique TCP connection. Each TCP connection is assigned a unique stream ID,
        which is used to track the packets that belong to that connection.
        The HTTP/2 stream ID, within a single TCP connection, multiple HTTP/2 streams can exist. Each HTTP/2 stream is
        identified by a unique stream ID within the context of that TCP connection. These stream IDs are used to
        multiplex multiple HTTP/2 requests and responses over a single TCP connection.

        A single TCP stream (connection) can contain multiple HTTP/2 streams. Each HTTP/2 stream is
        uniquely identified within the context of its TCP stream. The combination of the TCP stream ID and the
        HTTP/2 stream ID uniquely identifies an HTTP/2 stream within the network traffic.
    """
    def __init__(self, traffic: Sequence[DictLayers]):
        self.traffic = traffic
        self.stream_pairs: dict[tuple[int, int], Http2Stream] = {}
        self.parse_traffic()

    def parse_traffic(self) -> None:
        """
        Parse the traffic and extract the HTTP2 streams. It creates a dictionary for each HTTP2 stream.
        Each key is a tuple with the TCP stream ID and the HTTP2 stream ID.

        Identify each HTTP2 request and its associated HTTP2 response by following these steps:
        1. Iterate through packets: it loops through all packets obtained from the `traffic` object.
        2. Extract protocols: for each packet, it extracts the protocols from the `frame.protocols` field.
        3. Check for HTTP2 protocol: it checks if the packet contains the `http2` protocol.
        4. Extract the TCP stream ID: it retrieves the TCP stream ID from the `tcp.stream` field.
        5. Handle HTTP2 layer: it ensures the `http2` layer is a list of HTTP2 stream objects.
        6. Process each HTTP2 stream: for each HTTP2 stream in the `http2` layer:
           - extract stream information: it retrieves the stream type and stream ID.
           - filter relevant streams: it ignores streams that are not data (type 0) or headers (type 1).
           - create or update stream pair: it creates a new tuple of `(tcp_stream_id, http2_stream_id)` if it does not
             exist and appends the substream to the list.
        7. Process streams: after assembling the HTTP2 streams, it processes each stream to create the request and
           response objects.
        """
        # Assemble the HTTP2 streams
        for layers in self.traffic:
            protocols = layers['frame']['frame.protocols'].split(':')
            # Ignore non-http2 packets
            if 'http2' not in protocols:
                continue
            tcp_stream_id = int(layers['tcp']['tcp.stream'])

            # HTTP2 layer can be a list of streams or a single stream, force a list
            http2_layer = layers['http2']
            if not isinstance(http2_layer, list):
                http2_layer = [layers['http2']]

            for http2_layer_stream in http2_layer:
                stream = http2_layer_stream['http2.stream']
                http2_frame_type = int(stream.get('http2.type', -1))
                # Ignore streams that are not data or headers
                if http2_frame_type not in {0, 1}:
                    continue
                http2_stream_id = int(stream.get('http2.streamid', -1))
                # Create a new tuple of (tcp_stream_id, http2_stream_id) if it does not exist
                sid = (tcp_stream_id, http2_stream_id)
                if sid not in self.stream_pairs:
                    self.stream_pairs[sid] = Http2Stream(*sid)
                # Append the substream to the list
                self.stream_pairs[sid].append(stream, layers)

        # Process the streams, once for all
        for _k, http2_stream in self.stream_pairs.items():
            http2_stream.process()

    def get_http2_streams(self):
        return list(self.stream_pairs.values())

    def get_har_entries(self) -> list[HarEntry]:
        """
        Convert the HTTP2 traffic to HTTP Archive (HAR) format.

        :return: the HTTP2 traffic in HAR format
        """
        entries = []
        for stream in self.get_http2_streams():
            har_entry = stream.har_entry()
            if har_entry:
                entries.append(har_entry)
        return entries
