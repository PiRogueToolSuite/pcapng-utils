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


class WebSocketTextFrameIndex(int):
    pass


class WebSocketBinaryFrameIndex(int):
    pass


@dataclass(frozen=False, kw_only=True)
class WebSocketFrame:
    opcode: WebSocketOpcode
    # in websocket layers
    layer_index_first: int
    n_chunks: int
    # in frames
    frame_index: int | None = None


def get_websocket_payload_tree(ws_layer: dict[str, Any], /) -> tuple[dict[str, Any], str]:
    if "websocket.payload_tree" in ws_layer:
        return ws_layer["websocket.payload_tree"], "_tree"  # new tshark versions (>= v4.6)
    return ws_layer.get("websocket.payload", {}), ""


@dataclass(frozen=True)
class WebSocketFrames(FrameMixin, TCPIPMixin, CommunityIDMixin):
    """
    Ref: <https://www.wireshark.org/docs/dfref/w/websocket.html>

    Beware, there may be multiple websocket finalized messages (text or binary)
    within a single `websocket` layer.

    TODO: check on true examples for ping/pong events (not observed)
    """

    layers: DictLayers

    @cached_property
    def websocket_layers(self) -> list[dict[str, Any]]:
        wss = self.layers["websocket"]
        if isinstance(wss, dict):
            wss = [wss]
        return wss

    @cached_property
    def websocket_frames(self) -> list[WebSocketFrame]:
        frames = list[WebSocketFrame]()
        cur_frame_opcode: WebSocketOpcode | None = None
        cur_frame_chunks: int = 0
        for ix, ws in enumerate(self.websocket_layers):
            cur_opcode = int(ws["websocket.opcode"])
            cur_frame_chunks += 1
            if cur_frame_opcode is None:
                cur_frame_opcode = WebSocketOpcode(cur_opcode)  # should NOT be 0
            else:
                assert cur_opcode == 0, ws
            is_final = int(ws["websocket.fin"])
            assert is_final in {0, 1}, ws
            if is_final:
                frames.append(
                    WebSocketFrame(
                        opcode=cur_frame_opcode,
                        layer_index_first=ix - cur_frame_chunks + 1,
                        n_chunks=cur_frame_chunks,
                    )
                )
                cur_frame_opcode = None
                cur_frame_chunks = 0
            else:
                # ping/pong/close events may NOT be continued
                assert cur_frame_opcode in {WebSocketOpcode.text, WebSocketOpcode.binary}, self.websocket_layers
        assert cur_frame_opcode is None, self.websocket_layers  # otherwise <-> something not finalized
        # set frame index for text & binary messages
        txt_ix = 0
        bin_ix = 0
        for f in frames:
            match f.opcode:
                case WebSocketOpcode.text:
                    f.frame_index = txt_ix
                    txt_ix += 1
                case WebSocketOpcode.binary:
                    f.frame_index = bin_ix
                    bin_ix += 1
                case _:
                    continue
        return frames

    @cached_property
    def closure_frames(self) -> list[WebSocketFrame]:
        return [f for f in self.websocket_frames if f.opcode is WebSocketOpcode.close]

    @cached_property
    def has_closure(self) -> bool:
        return bool(self.closure_frames)

    @cached_property
    def regular_frames(self) -> list[WebSocketFrame]:
        return [f for f in self.websocket_frames if f.opcode is not WebSocketOpcode.close]

    @cached_property
    def has_regular(self) -> bool:
        return bool(self.regular_frames)

    @cached_property
    def n_text_frames(self) -> int:
        return len([1 for f in self.websocket_frames if f.opcode is WebSocketOpcode.text])

    @cached_property
    def n_binary_frames(self) -> int:
        return len([1 for f in self.websocket_frames if f.opcode is WebSocketOpcode.binary])

    def _get_regular_data(self, frame_ix: int | None, *, binary: bool) -> str:
        assert frame_ix is not None
        data_raw = self.layers["data_raw" if binary else "data-text-lines_raw"]
        n_frames = self.n_binary_frames if binary else self.n_text_frames
        if n_frames > 1:  # list of list
            assert (
                isinstance(self.layers["data" if binary else "data-text-lines"], list)  # data-raw is always a list
                and len(data_raw) == n_frames
            ), data_raw
            data_raw = data_raw[frame_ix]
        else:
            assert frame_ix == 0
        bytes_for_ix = get_tshark_bytes_from_raw(data_raw)
        return b64encode(bytes_for_ix).decode("ascii") if binary else bytes_for_ix.decode()

    def _get_ping_pong_data(self, layer_ix: int, *, ping: bool) -> str:
        ws_payload_tree, _ = get_websocket_payload_tree(self.websocket_layers[layer_ix])
        data_raw = ws_payload_tree.get(f"websocket.payload.{'ping' if ping else 'pong'}_raw")
        return get_tshark_bytes_from_raw(data_raw).decode() if data_raw is not None else ""

    def get_direction(self, src_dst_req: tuple[IPPort, IPPort], /) -> WebSocketDirection:
        if self.src_dst_ip_port == src_dst_req:
            return "send"
        assert self.src_dst_ip_port == src_dst_req[::-1], self
        return "receive"

    def closure_to_har(self, src_dst_req: tuple[IPPort, IPPort], /) -> dict[str, Any]:
        """
        Only to be called when there ARE some closures in WebSocket frames

        Nota:
        - we only retain first closure in case multiple (highly unlikely anyway)
        - we add type (direction) as compared to HTTP Toolkit schema
        so to distinguish between client/server closure messages
        """
        closure_frame = self.closure_frames[0]
        ws_payload, tree_suffix = get_websocket_payload_tree(self.websocket_layers[closure_frame.layer_index_first])
        close_payload = ws_payload.get(f"websocket.payload.close{tree_suffix}", {})
        opt_code = close_payload.get("websocket.payload.close.status_code")
        return {
            "type": self.get_direction(src_dst_req),
            "code": int(opt_code) if opt_code is not None else None,
            "reason": close_payload.get("websocket.payload.close.reason"),
            "time": self.timestamp,
        }

    def _regular_to_har(self, f: WebSocketFrame, typ: WebSocketDirection, /) -> dict[str, Any]:
        data: str
        match f.opcode:
            case WebSocketOpcode.text:
                data = self._get_regular_data(f.frame_index, binary=False)
            case WebSocketOpcode.binary:
                data = self._get_regular_data(f.frame_index, binary=True)
            case WebSocketOpcode.ping:
                assert typ == "send", self.websocket_layers
                data = self._get_ping_pong_data(f.layer_index_first, ping=True)
            case WebSocketOpcode.pong:
                assert typ == "receive", self.websocket_layers
                data = self._get_ping_pong_data(f.layer_index_first, ping=False)
            case _:
                raise ValueError(f"Unexpected {f}")
        return {
            "type": typ,
            "opcode": int(f.opcode),
            "data": data,
            "time": self.timestamp,
        }

    def regulars_to_har(self, src_dst_req: tuple[IPPort, IPPort], /) -> list[dict[str, Any]]:
        typ = self.get_direction(src_dst_req)
        return [self._regular_to_har(f, typ) for f in self.regular_frames]

    def sorting_key(self) -> float:
        return self.timestamp  # same for all messages within this instance


@dataclass(frozen=True)
class WebSocketConversation:
    src_dst_req: tuple[IPPort, IPPort]
    regular_messages: list[WebSocketFrames] = field(default_factory=list)
    closures: list[WebSocketFrames] = field(default_factory=list)

    @property
    def is_closed(self) -> bool:
        return bool(self.closures)

    def push(self, frames: WebSocketFrames) -> None:
        if frames.has_regular:
            assert not self.is_closed, (frames, self)
            self.regular_messages.append(frames)
        if frames.has_closure:
            self.closures.append(frames)

    def to_har(self) -> dict[str, Any]:
        """Ref: HTTP Toolkit schema"""
        d = {
            "_resourceType": "websocket",
            "_webSocketMessages": sum(
                (
                    frames.regulars_to_har(self.src_dst_req)
                    for frames in sorted(self.regular_messages, key=WebSocketFrames.sorting_key)
                ),
                [],
            ),
        }
        if self.closures:
            # we only retain the FIRST closure event (as in HTTP Toolkit)
            first_closure = sorted(self.closures, key=WebSocketFrames.sorting_key)[0]
            d["_webSocketClose"] = first_closure.closure_to_har(self.src_dst_req)
        return d
