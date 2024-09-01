import base64
from datetime import datetime

import pytz

from pcapng_utils.tshark.traffic import NetworkTrafficDump

http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE']


class HttpRequestResponse:
    """
    Base class for HTTP request and response packets. It wraps the packet data and provides methods to
    access the relevant information.
    """
    def __init__(self, packet: dict):
        self.packet: dict = packet
        self.http_layer = packet.get('http')
        self.raw_headers = ''

    @property
    def content_type(self):
        return self.http_layer.get('http.content_type', '')

    @property
    def raw_content(self):
        return self.http_layer.get('http.file_data', '')

    @property
    def decoded_content(self):
        printable = isinstance(self, HttpRequest)
        return NetworkTrafficDump.decode_data(self.raw_content, printable=printable)

    @property
    def base64_content(self):
        return NetworkTrafficDump.hex_content_to_base64(self.raw_content)

    @property
    def started_date(self) -> str:
        frame_time = self.packet.get('frame').get('frame.time_epoch')
        return datetime.fromtimestamp(float(frame_time), pytz.utc).isoformat()

    @property
    def headers(self):
        if isinstance(self, HttpRequest):
            self.raw_headers = self.http_layer.get('http.request.line', '')
        else:
            self.raw_headers = self.http_layer.get('http.response.line', '')
        processed_headers = []
        for header in self.raw_headers:
            try:
                key, value = header.split(': ', 1)
                processed_headers.append({
                    'name': key.strip(),
                    'value': value.replace('\r\n', '').strip()
                })
            except ValueError:
                return processed_headers
        return processed_headers


class HttpRequest(HttpRequestResponse):
    """
    Class to represent an HTTP request.
    """
    def __init__(self, packet: dict):
        super().__init__(packet)
        self.method: str = 'NA'
        self.parse_method()

    def parse_method(self):
        """
        Parse the HTTP method from the packet data.
        :return: the HTTP method
        """
        line = ''
        for k, _ in self.http_layer.items():
            if k.split(' ')[0] in http_methods:
                line = k
                break
        parts = line.split(' ')
        if len(parts) == 3:
            self.method = parts[0].strip()

    @property
    def sending_duration(self):
        return round(1000 * float(self.packet.get('frame').get('frame.time_delta', '0')), 2)

    def to_har(self):
        """
        Convert the HTTP request to HTTP Archive (HAR) format.
        :return: the HTTP request in HAR format
        """
        return {
            'startedDateTime': self.started_date,
            'method': self.method,
            'url': self.uri,
            'httpVersion': 'HTTP/1.1',
            'headers': self.headers,
            'queryString': [],
            'cookies': [],
            'headersSize': self.header_length,
            'bodySize': self.content_length,
            'postData': {
                'mimeType': self.content_type,
                'base64': self.base64_content,
                'text': self.decoded_content
            }
        }

    @property
    def uri(self):
        return self.http_layer.get('http.request.full_uri', '')

    @property
    def src_host(self) -> str:
        return self.packet.get('ip').get('ip.src_host', '')

    @property
    def dst_host(self) -> str:
        return self.packet.get('ip').get('ip.dst_host', '')

    @property
    def src_ip(self) -> str:
        return self.packet.get('ip').get('ip.src', '')

    @property
    def dst_ip(self) -> str:
        return self.packet.get('ip').get('ip.dst', '')

    @property
    def header_length(self):
        return len(''.join(self.raw_headers))

    @property
    def content_length(self):
        return len(base64.b64decode(self.base64_content))
        # return int(self.http_layer.get('http.content_length_header', '0'))


class HttpResponse(HttpRequestResponse):
    """
    Class to represent an HTTP response.
    """
    def __init__(self, packet: dict):
        super().__init__(packet)
        self.status_code = 0
        self.status_message = ''
        self.parse_status_line()

    def parse_status_line(self):
        """
        Parse the HTTP status line from the packet data.
        :return: the HTTP status code and message
        """
        line = ''
        for k, _ in self.http_layer.items():
            if k.startswith('HTTP/'):
                line = k
            elif k.startswith(' [truncated]'):
                line = k.replace(' [truncated]', '') + ' HTTP/1.1'
            elif k.split(' ')[0] in http_methods:
                line = k
        parts = line.split(' ', 2)
        if len(parts) == 3:
            self.status_code = int(parts[1].strip())
            self.status_message = parts[2].strip('\\r\\n')

    def to_har(self):
        """
        Convert the HTTP response to HTTP Archive (HAR) format.
        :return: the HTTP response in HAR format
        """
        return {
            'startedDateTime': self.started_date,
            'status': self.status_code,
            'statusText': self.status_message,
            'httpVersion': 'HTTP/1.1',
            'headers': self.headers,
            'cookies': [],
            'headersSize': self.header_length,
            'bodySize': self.content_length,
            'content': {
                'size': self.content_length,
                'encoding': 'base64',
                'mimeType': self.content_type,
                'base64': self.base64_content,
                'text': self.base64_content  # decoded_content
            }
        }

    @property
    def receiving_duration(self):
        return round(1000 * float(self.http_layer.get('http.time', '0')), 2)

    @property
    def header_length(self):
        return len(''.join(self.raw_headers))

    @property
    def content_length(self):
        return len(self.decoded_content)


class HttpConversation:
    """
    Class to represent an HTTP conversation composed of a request and a response.
    """
    def __init__(self, request_frame: dict, response_frame: dict):
        self.request: HttpRequest = HttpRequest(request_frame)
        self.response: HttpResponse = HttpResponse(response_frame)

    @property
    def waiting_duration(self) -> float:
        start_time = float(self.request.packet.get('frame').get('frame.time_epoch'))
        stop_time = float(self.response.packet.get('frame').get('frame.time_epoch'))
        return round(1000 * (stop_time - start_time), 2)

    def to_har(self):
        """
        Convert the HTTP conversation to HTTP Archive (HAR) format.
        :return: the HTTP conversation (request and response) in HAR format
        """
        return {
            'startedDateTime': self.request.started_date,
            'timestamp': float(self.request.packet.get('frame').get('frame.time_epoch')),
            'time': 0,
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
    - `http.file_data`: The data in hexadecimal format.
    """
    def __init__(self, traffic: NetworkTrafficDump):
        self.traffic: NetworkTrafficDump = traffic
        self.conversations: list[HttpConversation] = []
        self.parse_traffic()

    def parse_traffic(self):
        """
        Parse the HTTP network traffic and extract the request-response pairs.
        
        Identify each HTTP request and its associated HTTP response by following these steps:
        1. Iterate through packets: It loops through all packets obtained from the `traffic` object.
        2. Extract layers: For each packet, it extracts the layers from the `_source` key.
        3. Check protocols: It checks if the packet contains the `http` protocol by examining the `frame.protocols`
           field.
        4. Identify http requests: It checks if the packet contains an HTTP request by looking for the `http.request`
           key in the `http` layer.
        5. Find associated response: If the packet is an HTTP request and contains the `http.response_in` key, it
           retrieves the corresponding response packet using the `get_packet_by_number` method with the response number.
        6. Create conversation: It creates an `HttpConversation` object with the request and response packets and
           appends it to the `conversations` list.
        """
        for packet in self.traffic.get_packets():
            packet = packet.get('_source').get('layers')
            protocols = packet.get('frame').get('frame.protocols').split(':')
            if 'http' not in protocols:
                continue
            http_layer = packet.get('http')
            if 'http.request' not in http_layer:
                continue
            if 'http.response_in' in http_layer:
                # This is a request
                response_packet = self.traffic.get_packet_by_number(int(http_layer.get('http.response_in')))
                self.conversations.append(HttpConversation(packet, response_packet))

    def get_har_entries(self):
        """
        Convert the HTTP network traffic to HTTP Archive (HAR) format.
        :return: the HTTP network traffic in HAR format
        """
        entries = []
        for http_conversation in self.conversations:
            entries.append(http_conversation.to_har())
        return entries
