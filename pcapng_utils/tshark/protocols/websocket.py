from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cached_property
from enum import IntEnum
from typing import Literal, Any
from base64 import b64encode

from ..types import DictLayers, IPPort
from ..layers import FrameMixin, TCPIPMixin, CommunityIDMixin
from ..utils import get_tshark_bytes_from_raw


class WebSocketOpcode(IntEnum):
    """Ref: <https://datatracker.ietf.org/doc/html/rfc6455#section-11.8>"""

    # continuation = 0 # not used (reassembled by tshark)
    text = 1
    binary = 2
    close = 8
    ping = 9
    pong = 10


WebSocketDirection = Literal["send", "receive"]


def is_websocket_conversation(
    req_http1_layer: Mapping[str, Any], resp_http1_layer: Mapping[str, Any], *, response_code: int
) -> bool:
    return (
        req_http1_layer.get("http.upgrade") == "websocket"
        and resp_http1_layer.get("http.upgrade") == "websocket"
        and response_code == 101
    )


@dataclass(frozen=True)
class WebSocketFrame(FrameMixin, TCPIPMixin, CommunityIDMixin):
    layers: DictLayers

    @cached_property
    def websocket_layers(self) -> list[dict[str, Any]]:
        wss = self.layers["websocket"]
        if isinstance(wss, dict):
            wss = [wss]
        return wss

    @cached_property
    def opcode(self) -> WebSocketOpcode:
        opcodes = {op for ws in self.websocket_layers if (op := int(ws["websocket.opcode"])) != 0}
        assert len(opcodes) == 1, (self.frame_nb, opcodes)
        return WebSocketOpcode(next(iter(opcodes)))

    @property
    def is_closure(self) -> bool:
        return self.opcode is WebSocketOpcode.close

    @property
    def text(self) -> str:
        return get_tshark_bytes_from_raw(self.layers["data-text-lines_raw"]).decode()

    @property
    def data(self) -> bytes:
        return get_tshark_bytes_from_raw(self.layers["data_raw"])

    def get_direction(self, src_dst_req: tuple[IPPort, IPPort], /) -> WebSocketDirection:
        if self.src_dst_ip_port == src_dst_req:
            return "send"
        assert self.src_dst_ip_port == src_dst_req[::-1], self
        return "receive"

    def to_har(self, src_dst_req: tuple[IPPort, IPPort], /) -> dict[str, Any]:
        """Ref: <https://www.wireshark.org/docs/dfref/w/websocket.html>"""
        # TODO: check on true examples for closure & ping/pong
        if self.is_closure:
            # no direction in HTTP Toolkit schema despite there could be both requester/server closure messages
            assert len(self.websocket_layers) == 1, self.websocket_layers
            close = self.websocket_layers[0]
            return {
                "code": int(close["websocket.payload.close.status_code"]),
                "reason": close["websocket.payload.close.reason"],
                "time": self.timestamp,
            }
        # true message
        data = b64encode(self.data).decode("ascii") if self.opcode == WebSocketOpcode.binary else self.text
        typ = self.get_direction(src_dst_req)
        expected_typ = dict[WebSocketOpcode, WebSocketDirection](
            {
                WebSocketOpcode.ping: "send",
                WebSocketOpcode.pong: "receive",
            }
        ).get(self.opcode)
        if expected_typ is not None:
            assert typ == expected_typ, self.websocket_layers
        return {
            "type": typ,
            "opcode": int(self.opcode),
            "data": data,
            "time": self.timestamp,
        }


@dataclass(frozen=True)
class WebSocketConversation:
    src_dst_req: tuple[IPPort, IPPort]
    true_messages: list[WebSocketFrame] = field(default_factory=list)
    closures: list[WebSocketFrame] = field(default_factory=list)

    @property
    def is_closed(self) -> bool:
        return bool(self.closures)

    def append(self, frame: WebSocketFrame) -> bool:
        if frame.is_closure:
            self.closures.append(frame)
            return True
        if self.is_closed:
            return False
        self.true_messages.append(frame)
        return True

    def to_har(self) -> dict[str, Any]:
        """Ref: HTTP Toolkit schema"""
        d = {
            "_resourceType": "websocket",
            "_webSocketMessages": [msg.to_har(self.src_dst_req) for msg in self.true_messages],
        }
        if self.closures:
            # we only retain the FIRST closure message (as in HTTP Toolkit)
            d["_webSocketClose"] = self.closures[0].to_har(self.src_dst_req)
        return d
