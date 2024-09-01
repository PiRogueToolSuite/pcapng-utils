from datetime import datetime
from typing import Optional

import pytz

from pcapng_utils.tshark.traffic import NetworkTrafficDump


class Http2Substream:
    """
    Class to represent a HTTP2 substream. It contains the layers of the packet and the metadata of the substream.
    Wrap the raw HTTP2 substream and the frame layers to extract the relevant information.
    """
    keep_layers = ['ip', 'frame']

    def __init__(self, raw_http2_substream: dict, frame: dict):
        self.packet_layers = frame.get('_source').get('layers')
        clean_layers = {}
        for layer, data in self.packet_layers.items():
            if layer in Http2Substream.keep_layers:
                clean_layers[layer] = data
        self.packet_layers: dict = clean_layers
        self.raw_http2_substream: dict = raw_http2_substream

    @property
    def http2_flags(self) -> int:
        return int(self.raw_http2_substream.get('http2.flags', '0x0'), 0)

    @property
    def http2_type(self) -> int:
        return int(self.raw_http2_substream.get('http2.type', '-1'))

    @property
    def ip_layer(self) -> dict:
        return self.packet_layers.get('ip', {})

    @property
    def frame_layer(self) -> dict:
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
    def raw_headers(self) -> list[dict]:
        return self.raw_http2_substream.get('http2.header', [])

    @property
    def started_date(self) -> str:
        frame_time = self.frame_layer.get('frame.time_epoch')
        return datetime.fromtimestamp(float(frame_time), pytz.utc).isoformat()


class Http2RequestResponse:
    """
    Base class to represent a HTTP2 request or response. It contains the headers and data of the request or response.
    Implements the common properties of a HTTP2 request or response.
    """
    def __init__(self, substreams: list[Http2Substream]):
        self.substreams = substreams
        self.headers, self.data, self.headers_stream, self.data_stream = Http2Helper.get_headers_and_data(substreams)

    @property
    def http_version(self) -> str:
        return 'HTTP/2'

    @property
    def raw_content(self) -> str:
        if not self.data_stream:
            return ''
        if 'http2.body.fragments' in self.data_stream.raw_http2_substream:
            return self.data_stream.raw_http2_substream['http2.body.fragments'].get('http2.body.reassembled.data', '')
        if 'http2.data.data' in self.data_stream.raw_http2_substream:
            return self.data_stream.raw_http2_substream.get('http2.data.data', '')
        return ''

    @property
    def base64_content(self):
        return NetworkTrafficDump.hex_content_to_base64(self.raw_content)

    @property
    def uri(self) -> str:
        return self.headers_stream.raw_http2_substream.get('http2.request.full_uri', '')

    @property
    def header_length(self) -> int:
        return int(self.headers_stream.raw_http2_substream.get('http2.header.length', 0))

    @property
    def body_length(self) -> int:
        length = self.headers_stream.raw_http2_substream.get('http2.length', '0')
        if isinstance(self, Http2Response) and 'http2.body.fragments' in self.data_stream.raw_http2_substream:
            length = self.data_stream.raw_http2_substream['http2.body.fragments'].get('http2.body.reassembled.length',
                                                                                      0)
        return int(length)

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
        return 'application/octet-stream'


class Http2Request(Http2RequestResponse):
    """
    Class to represent a HTTP2 request. It contains the headers and data of the request.
    """
    def __init__(self, substreams: list[Http2Substream]):
        super().__init__(substreams)

    @property
    def sending_duration(self) -> float:
        start_time = float(self.headers_stream.frame_layer.get('frame.time_epoch', 0))
        if not self.data_stream:
            return 1
        stop_time = float(self.data_stream.frame_layer.get('frame.time_epoch', 0))
        return round(1000 * (stop_time - start_time), 2)

    def __str__(self):
        return f'Request - {len(self.substreams)} substreams\nHeaders: {self.headers}\nData: {self.data}'


class Http2Response(Http2RequestResponse):
    """
    Class to represent a HTTP2 response. It contains the headers and data of the response.
    """
    def __init__(self, substreams: list[Http2Substream]):
        super().__init__(substreams)

    @property
    def receiving_duration(self) -> float:
        start_time = float(self.headers_stream.frame_layer.get('frame.time_epoch', 0))
        stop_time = float(self.data_stream.frame_layer.get('frame.time_epoch', 0))
        return round(1000 * (stop_time - start_time), 2)

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
     +--------------------------------------
     | Http2SubStream 4    | Response headers (type: 1)
     | Http2SubStream ...  | Response data (type: 0, flags: 0x0) - partial data
     | Http2SubStream 6    | Response data (type: 0, flags: 0x1) - end of stream, contains reassembled data
     +--------------------------------------
     Each HTTP2 steam is defined by a tuple (tcp stream, http2 stream) and contains both request and response objects.
    """
    def __init__(self, tcp_stream_id, http2_stream_id):
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

    def append(self, substream: dict, frame):
        """
        Append a new substream to the HTTP2 stream.

        :param substream: the substream to be added
        :param frame: the frame containing the substream. A frame can contain multiple substreams.
        """
        self.substreams.append(Http2Substream(substream, frame))

    @property
    def waiting_duration(self) -> float:
        if not self.request.data_stream:
            start_time = float(self.request.headers_stream.frame_layer.get('frame.time_epoch', 0))
        else:
            start_time = float(self.request.data_stream.frame_layer.get('frame.time_epoch', 0))
        if not self.response:
            return 0
        if self.response.data_stream:
            stop_time = float(self.response.headers_stream.frame_layer.get('frame.time_epoch', 0))
        else:
            return 0
        return round(1000 * (stop_time - start_time), 2)

    def har_entry(self):
        """
        Create a HAR entry for the HTTP2 stream. It contains the request and response objects.

        :return: the HAR entry for the HTTP2 stream
        """
        self.process()
        request_har = Http2Helper.to_har(self.request)
        response_har = Http2Helper.to_har(self.response)
        if not request_har or not response_har:
            return None
        return {
            'startedDateTime': self.request.headers_stream.started_date,
            'timestamp': float(self.response.headers_stream.frame_layer.get('frame.time_epoch', 0)),
            'time': 0,
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
    def get_raw_reassembled_data(substream: dict) -> str:
        """
        Find the reassembled data in the substream.

        :param substream: the substream to be analyzed
        :return: the raw reassembled data (in hex format) if it exists, otherwise an empty string
        """
        for k, v in substream.items():
            if k.startswith('Content-'):
                return v.get('http2.data.data', '')
        if 'http2.body.fragments' in substream:
            return substream['http2.body.fragments'].get('http2.body.reassembled.data', '')
        if 'http2.data.data' in substream:
            return substream.get('http2.data.data', '')
        return ''

    def process(self):
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
            response_frame_number = int(substream.raw_http2_substream.get('http2.response_in', '-1'))
            if response_frame_number > 0:
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
    def get_headers(substream: Http2Substream):
        """
        Extract the headers from the substream.

        :param substream: the substream to be analyzed
        :return: the headers of the substream
        """
        headers = []
        stream_type = substream.http2_type
        if stream_type == 1:
            for header in substream.raw_headers:
                headers.append({
                    'name': header.get('http2.header.name', ''),
                    'value': header.get('http2.header.value', '')
                })
        return headers

    @staticmethod
    def to_har(message: Http2RequestResponse):
        """
        Convert the HTTP2 request or response to a HAR entry.

        :param message: the HTTP2 request or response to be converted
        :return: the HAR entry for the HTTP2 request or response
        """
        if len(message.substreams) == 0:
            return None
        is_request = isinstance(message, Http2Request)
        entry = {
            'httpVersion': message.http_version,
            'headers': message.headers,
            'queryString': [],
            'cookies': [],
            'headersSize': message.header_length,
            'bodySize': message.body_length,
        }
        if is_request:
            entry['method'] = message.http_method
            entry['url'] = message.uri
            entry['postData'] = {
                'mimeType': message.content_type,
                'base64': message.base64_content,
                'text': message.data,
                'params': []
            }
        else:
            entry['status'] = message.http_status
            entry['statusText'] = ''
            entry['redirectURL'] = ''
            entry['content'] = {
                'size': message.body_length,
                'mimeType': message.content_type,
                'base64': message.base64_content,
                'text': message.data
            }
        return entry

    @staticmethod
    def get_data(substream: Http2Substream):
        """
        Extract the data from the substream. First check if the substream is a data substream.

        :param substream: the substream to be analyzed
        :return: the reassembled data if it is a data substream, otherwise None
        """
        stream_type = substream.http2_type
        stream_flags = substream.http2_flags
        if stream_type == 0 and stream_flags & 0x01:
            return Http2Stream.get_raw_reassembled_data(substream.raw_http2_substream)
        return None

    @staticmethod
    def get_headers_and_data(substreams: list[Http2Substream]):
        """
        Identify the headers and data substreams and return them. The substreams are identified by their type and flags:
        - Headers substream: type 1
        - Data substream: type 0 and flags 0x01
        And ignore the rest of the substreams.

        :param substreams: the substreams of a HTTP2 stream
        :return: the headers and data substreams regardless if it is a request or a response
        """
        headers = []
        data = None
        headers_stream = None
        data_stream = None

        for substream in substreams:
            stream_type = substream.http2_type
            stream_flags = substream.http2_flags
            # Parse headers (HTTP2 substream marked as headers)
            if stream_type == 1:
                headers = Http2Helper.get_headers(substream)
                headers_stream = substream
            # Parse data (HTTP2 substream marked as data and flagged end of stream)
            if stream_type == 0 and stream_flags & 0x01:
                data = NetworkTrafficDump.decode_data(Http2Helper.get_data(substream))
                data_stream = substream

        return headers, data, headers_stream, data_stream


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
    def __init__(self, traffic: NetworkTrafficDump):
        self.traffic: NetworkTrafficDump = traffic
        self.stream_pairs: dict[(str, str), Http2Stream] = {}
        self.parse_traffic()

    def parse_traffic(self):
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
        for frame in self.traffic.get_packets():
            protocols = frame['_source']['layers']['frame']['frame.protocols'].split(':')
            # Ignore non-http2 packets
            if 'http2' not in protocols:
                continue
            tcp_stream_id = int(frame['_source']['layers']['tcp'].get('tcp.stream', -1))

            # HTTP2 layer can be a list or a single object, force to be a list of HTTP2 steam objects
            http2_layer = frame['_source']['layers']['http2']
            if type(http2_layer) is not list:
                http2_layer = [frame['_source']['layers']['http2']]

            stream_index = 0
            for http2_layer_stream in http2_layer:
                stream = http2_layer_stream.get('http2.stream')
                http2_frame_type = int(stream.get('http2.type', -1))
                # Ignore streams that are not data or headers
                if http2_frame_type not in [0, 1]:
                    continue
                http2_stream_id = int(stream.get('http2.streamid', -1))
                # Create a new tuple of (tcp_stream_id, http2_stream_id) if it does not exist
                if (tcp_stream_id, http2_stream_id) not in self.stream_pairs:
                    self.stream_pairs[(tcp_stream_id, http2_stream_id)] = Http2Stream(tcp_stream_id, http2_stream_id)
                # Append the substream to the list
                self.stream_pairs[(tcp_stream_id, http2_stream_id)].append(stream, frame)
                stream_index += 1
        # Process the streams
        for _, http2_steam in self.stream_pairs.items():
            http2_steam.process()

    def get_http2_streams(self):
        return list(self.stream_pairs.values())

    def get_har_entries(self):
        """
        Convert the HTTP2 traffic to HTTP Archive (HAR) format.

        :return: the HTTP2 traffic in HAR format
        """
        entries = []
        for key, stream in self.stream_pairs.items():
            har_entry = stream.har_entry()
            if har_entry:
                entries.append(har_entry)
        return entries
