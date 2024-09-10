import warnings
from datetime import datetime
from typing import Sequence, Mapping, ClassVar, Optional, Any

import pytz

from pcapng_utils.tshark.utils import Payload, DictLayers

NameValueDict = Mapping[str, str]


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
        return self.packet_layers.get('ip', {})

    @property
    def frame_layer(self) -> dict[str, Any]:
        return self.packet_layers.get('frame', {})

    @property
    def src_host(self) -> str:
        return self.ip_layer.get('ip.src_host', '')

    @property
    def dst_host(self) -> str:
        return self.ip_layer.get('ip.dst_host', '')

    @property
    def src_ip(self) -> str:
        return self.ip_layer.get('ip.src', '')

    @property
    def dst_ip(self) -> str:
        return self.ip_layer.get('ip.dst', '')

    @property
    def raw_headers(self) -> list[dict[str, str]]:
        return self.raw_http2_substream.get('http2.header', [])

    @property
    def started_date(self) -> str:
        frame_time: str = self.frame_layer['frame.time_epoch']
        return datetime.fromtimestamp(float(frame_time), pytz.utc).isoformat()


class Http2RequestResponse:
    """
    Base class to represent a HTTP2 request or response. It contains the headers and data of the request or response.
    Implements the common properties of a HTTP2 request or response.
    """
    FALLBACK_CONTENT_TYPE: ClassVar = 'application/octet-stream'

    def __init__(self, substreams: list[Http2Substream]):
        self.substreams = substreams
        self.headers, self.data, self.headers_streams, self.data_streams = Http2Helper.get_headers_and_data(substreams)

    @property
    def http_version(self) -> str:
        return 'HTTP/2'

    @property
    def header_length(self) -> int:
        # The effective payload sent over network has bytes size `http2.length` <= `http2.headers.length`
        # (because special headers - like `:status` - have predefined codes)
        return sum(int(s.raw_http2_substream.get('http2.length', 0)) for s in self.headers_streams)

    @property
    def body_length(self) -> int:
        """
        <!> In Tshark < 4.2.0:
        - we do not have `http2.body.*`
        - `http2.length` is also populated for header substreams
        """
        declared_size = sum(int(s.raw_http2_substream.get('http2.length', 0)) for s in self.data_streams)
        if declared_size != self.data.size:
            warnings.warn(
                f"{self}\nBody length mismatch: "
                f"declared ({declared_size}) != computed ({self.data.size})"
            )
        return declared_size

    @property
    def http_status(self) -> int:
        status_code = 0
        for header in self.headers:
            if header.get('name', '') == ':status':
                status_code = header.get('value', 0)
        return int(status_code)

    @property
    def http_method(self) -> str:
        for header in self.headers:
            if header.get('name', '') == ':method':
                return header.get('value', '')
        return ''

    @property
    def content_type(self) -> str:
        for header in self.headers:
            if header.get('name', '') == 'content-type':
                return header.get('value', '')
        return self.FALLBACK_CONTENT_TYPE


def _get_stream_time_s(s: Http2Substream) -> float:
    return float(s.frame_layer.get('frame.time_epoch', 0))


def _get_duration_ms(r: Http2RequestResponse) -> float:
    return round(1000 * (_get_stream_time_s(r.substreams[-1]) - _get_stream_time_s(r.substreams[0])), 2)


class Http2Request(Http2RequestResponse):
    """
    Class to represent a HTTP2 request. It contains the headers and data of the request.
    """
    @property
    def uri(self) -> str:
        return self.headers_streams[0].raw_http2_substream.get('http2.request.full_uri', '')

    @property
    def sending_duration(self) -> float:
        return _get_duration_ms(self)

    def __str__(self):
        return f'Request - {len(self.substreams)} substreams\nHeaders: {self.headers}\nData: {self.data}'


class Http2Response(Http2RequestResponse):
    """
    Class to represent a HTTP2 response. It contains the headers and data of the response.
    """
    @property
    def receiving_duration(self) -> float:
        return _get_duration_ms(self)

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
        assert self.request is not None
        start_stream = self.request.substreams[-1]
        resp_stream = self.response.substreams[0]
        return round(1000 * (_get_stream_time_s(resp_stream) - _get_stream_time_s(start_stream)), 2)

    def har_entry(self) -> Optional[dict[str, Any]]:
        """
        Create a HAR entry for the HTTP2 stream. It contains the request and response objects.

        :return: the HAR entry for the HTTP2 stream
        """
        assert self.request is not None
        assert self.response is not None
        request_har = Http2Helper.to_har(self.request)
        response_har = Http2Helper.to_har(self.response)
        if not request_har or not response_har:
            return None
        return {
            'startedDateTime': self.request.headers_streams[0].started_date,
            'timestamp': _get_stream_time_s(self.response.headers_streams[0]),
            'time': 0,  # not used
            'timings': {
                'send': self.request.sending_duration,
                'wait': self.waiting_duration,
                'receive': self.response.receiving_duration
            },
            'cache': {},
            'request': request_har,
            'response': response_har,
        }

    @staticmethod
    def get_raw_data(substream: dict[str, Any]) -> str:
        """
        Find the data in the substream.

        :param substream: the substream to be analyzed
        :return: the raw reassembled data (in hex format) if it exists, otherwise an empty string
        """
        #if 'http2.body.fragments' in substream:
        #    return substream['http2.body.fragments']['http2.body.reassembled.data']  # not available in < 4.2.0
        if 'http2.data.data' in substream:
            return substream['http2.data.data']
        for k, v in substream.items():
            if k.startswith('Content-') and 'http2.data.data' in v:
                return v['http2.data.data']
        return ''

    def process(self) -> None:
        """
        Process the substreams and create the request and response objects accordingly. Substreams are processed in
        order, the first substreams are request headers, followed by request data, and finally the response headers and
        data. The reassembled data is used to create the request and response objects.

        Request substreams are identified by the presence of the 'http2.response_in' key in the raw stream. If no
        response substream is found, the request object is created with the first substreams.

        It retrieves the source and destination IP addresses from the first substream to identify the substreams that
        belong to the request. The response substreams are identified by checking their source IP address matches
        the destination IP address of the first substream.
        """
        src = self.substreams[0].src_ip
        dst = self.substreams[0].dst_ip
        # Find request frame and its associated substreams
        for substream in self.substreams:
            response_frame_number = int(substream.raw_http2_substream.get('http2.response_in', -1))
            if response_frame_number > 0:  # This is a request
                src = substream.src_ip
                dst = substream.dst_ip
        # Create the request and response objects with their associated substreams
        self.request = Http2Request([substream for substream in self.substreams if substream.src_ip == src])
        self.response = Http2Response([substream for substream in self.substreams if substream.src_ip == dst])

    def get_request(self):
        return self.request

    def get_response(self):
        return self.response

    def __str__(self):
        return (f'\nTCP Stream: {self.tcp_stream_id}, '
                f'HTTP2 Stream: {self.http2_stream_id}, '
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
        # stream_flags = substream.http2_flags
        return stream_type == 0 # and bool(stream_flags & 0x01)

    @staticmethod
    def get_headers(substream: Http2Substream) -> list[NameValueDict]:
        """
        Extract the headers from the substream (precondition: it is a header substream).

        :param substream: the substream to be analyzed
        :return: the headers of the substream
        """
        headers: list[NameValueDict] = []
        for header in substream.raw_headers:
            headers.append({
                'name': header.get('http2.header.name', ''),
                'value': header.get('http2.header.value', '')
            })
        return headers

    @staticmethod
    def to_har(message: Http2RequestResponse) -> Optional[dict[str, Any]]:
        """
        Convert the HTTP2 request or response to a HAR entry.

        :param message: the HTTP2 request or response to be converted
        :return: the HAR entry for the HTTP2 request or response
        """
        if len(message.substreams) == 0:
            return None
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
                    'params': [],  # TODO?
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
    def get_data(substream: Http2Substream) -> str:
        """
        Extract the data from the substream (precondition: the substream is a data substream).

        :param substream: the substream to be analyzed
        :return: the reassembled data if it is a data substream, otherwise None
        """
        return Http2Stream.get_raw_data(substream.raw_http2_substream)

    @classmethod
    def get_headers_and_data(cls, substreams: list[Http2Substream]):
        """
        Identify the headers and data substreams and return them. The substreams are identified by their type and flags:
        - Headers substream: type 1
        - Data substream: type 0 and flags 0x01
        And ignore the rest of the substreams.

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
                datas.append(Payload.from_unsure_tshark_data(Http2Helper.get_data(substream)))

        assert headers_streams

        return headers, Payload.concat(*datas), headers_streams, data_streams


class Http2Traffic:
    """
    Class to represent the HTTP2 traffic. It contains the HTTP2 streams and the parsed traffic data.

    In HTTP/2, frames are the smallest unit of communication. Each frame has a specific type and can have
        associated flags.

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

            # HTTP2 layer can be a list or a single object, force to be a list of HTTP2 steam objects
            http2_layer = layers['http2']
            if type(http2_layer) is not list:
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

    def get_har_entries(self) -> list[dict[str, Any]]:
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
