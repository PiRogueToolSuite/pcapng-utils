import logging
from base64 import b64encode
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from enum import IntEnum
from functools import cached_property
from typing import Any, Final, Literal

from ..layers import CommunityIDMixin, FrameMixin, TCPIPMixin
from ..types import IPPort, TsharkRaw
from ..utils import get_tshark_bytes_from_raw

LOGGER = logging.getLogger(__name__)


WebSocketDirection = Literal["send", "receive"]


class WebSocketOpcode(IntEnum):
    """Ref: <https://datatracker.ietf.org/doc/html/rfc6455#section-11.8>"""

    # continuation = 0  # not used as is
    text = 1
    binary = 2
    close = 8
    ping = 9
    pong = 10


CONTINUABLE_OPCODES = frozenset({WebSocketOpcode.text, WebSocketOpcode.binary})
"""ping/pong/close events may NOT be continued"""


def is_websocket_conversation(
    req_http1_layer: Mapping[str, Any],
    resp_http1_layer: Mapping[str, Any],
    *,
    response_code: int,
) -> bool:
    return (
        req_http1_layer.get("http.upgrade") == "websocket"
        and resp_http1_layer.get("http.upgrade") == "websocket"
        and response_code == 101
    )


def _get_ws_data_key(*, binary: bool) -> str:
    return "data" if binary else "data-text-lines"


def _asserted_is_dict(d: Any) -> dict[str, Any]:
    assert isinstance(d, dict), d
    return d


def _try_get_websocket_payload_tree(ws_layer: dict[str, Any], /) -> tuple[dict[str, Any], str] | None:
    if "websocket.payload_tree" in ws_layer:  # new tshark versions (>= v4.6)
        return (_asserted_is_dict(ws_layer["websocket.payload_tree"]), "_tree")
    # in old tshark versions: `websocket.payload` is either str or dict (the tree itself)
    # this field may also be present in new versions, but then it is always a string
    payload = ws_layer.get("websocket.payload")
    if not payload or isinstance(payload, str):
        return None
    return _asserted_is_dict(payload), ""


def _get_websocket_payload_tree(
    ws_layer: dict[str, Any], /, *, msg: "WebSocketMessageInNetworkFramePossiblyIncomplete", frame_nb: int
) -> tuple[dict[str, Any], str]:
    ptree_tup = _try_get_websocket_payload_tree(ws_layer)
    if ptree_tup is None:
        LOGGER.debug(f"Frame #{frame_nb}: no websocket payload tree for {msg!r}")
        return {}, ""
    return ptree_tup


@dataclass(frozen=False, kw_only=True)
class WebSocketIndicesInSingleNetworkFrame:

    # order in websocket layers of the network frame
    websocket_layers_start_index: Final[int]  # type: ignore[misc]
    n_chunks: int = 1  # to be progressively incremented

    # order in websocket messages (order is per continuable message type [text or binary])
    message_index_for_opcode: int | None = None  # to be determined later


@dataclass(frozen=False, kw_only=True)
class WebSocketMessageInNetworkFramePossiblyIncomplete:
    opcode: WebSocketOpcode | None
    """
    Opcode of websocket message is None <=> the message was started before the current network frame;
    in such cases, the actual opcode will be set later based on opcode of the initiating message
    """

    indices_in_this_network_frame: WebSocketIndicesInSingleNetworkFrame
    """Offsets and size of this message within the current network frame"""

    initiated_in_this_network_frame: Final[bool] = True
    """Whether this websocket message was initiated in the current network frame"""

    finalized_in_this_network_frame: bool = False
    """Whether this websocket message was finalized in the current network frame"""

    def get_subset_of_websocket_layers(self, all_ws_layers: list[dict[str, Any]], /) -> list[dict[str, Any]]:
        # layers are contiguous (no interleaving)
        return [
            all_ws_layers[i + self.indices_in_this_network_frame.websocket_layers_start_index]
            for i in range(self.indices_in_this_network_frame.n_chunks)
        ]

    def get_raw_text_payload_manually(self, all_ws_layers: list[dict[str, Any]], /) -> TsharkRaw:
        sub_ws_layers = self.get_subset_of_websocket_layers(all_ws_layers)
        # <!> the payload tree is not always on the finalized fragment...
        payload_trees = [
            ptree_tup for wsl in sub_ws_layers if (ptree_tup := _try_get_websocket_payload_tree(wsl)) is not None
        ]
        if not payload_trees:
            assert len(sub_ws_layers) == 1
            wsl = sub_ws_layers[0]
            assert int(wsl["websocket.opcode"]) == WebSocketOpcode.text
            assert int(wsl["websocket.fin"]) == 1
            return wsl["websocket.payload_raw"]
        assert len(payload_trees) == 1
        ptree, _ = payload_trees[0]
        return ptree["websocket.payload.text_raw"]


@dataclass(frozen=False)
class WebSocketMessagesInNetworkFramePossiblyIncomplete(FrameMixin, TCPIPMixin, CommunityIDMixin):
    """
    Ref: <https://www.wireshark.org/docs/dfref/w/websocket.html>

    Beware:
    - there may be multiple websocket finalized messages (text or binary)
    within the `websocket` layers of a single network frame
    - there may be websocket messages split in multiple network frames (i.e. `websocket` layers
    ending with an incomplete websocket message + `websocket` layers of next network frame(s)
    starting with a continuation opcode, but websocket chunks shall never be interleaved)

    TODO: check on true examples for ping/pong events (not observed)
    """

    layers: Final[MutableMapping[str, Any]]  # type: ignore[misc]
    # nota: not `DictLayers` since mutability is needed (because of manual fixes in some rare cases)

    _has_all_metadata: bool = False

    @cached_property
    def websocket_layers(self) -> list[dict[str, Any]]:
        wss = self.layers["websocket"]
        if isinstance(wss, dict):
            wss = [wss]
        return wss

    @cached_property
    def websocket_messages(self) -> list[WebSocketMessageInNetworkFramePossiblyIncomplete]:
        finalized_messages: list[WebSocketMessageInNetworkFramePossiblyIncomplete] = []
        cur_msg: WebSocketMessageInNetworkFramePossiblyIncomplete | None = None
        for ws_ix, ws in enumerate(self.websocket_layers):
            cur_opcode = int(ws["websocket.opcode"])
            is_continuation = cur_opcode == 0
            if cur_msg is None:
                # <!> opcode may be 0 (continuation from un-finalized message from previous network frame)
                # but only if no finalization occurred in the current network frame yet
                if is_continuation and finalized_messages:
                    raise ValueError(
                        f"Frame #{self.frame_nb}: Websocket layer #{ws_ix}: Received a continuation opcode "
                        "while a previous websocket message was finalized and no other message was started again"
                    )
                cur_msg = WebSocketMessageInNetworkFramePossiblyIncomplete(
                    opcode=None if is_continuation else WebSocketOpcode(cur_opcode),
                    initiated_in_this_network_frame=not is_continuation,
                    indices_in_this_network_frame=WebSocketIndicesInSingleNetworkFrame(
                        websocket_layers_start_index=ws_ix
                    ),
                )
            else:
                assert is_continuation, (self.frame_nb, ws_ix)
                assert cur_msg.opcode != WebSocketOpcode.binary, self.frame_nb
                cur_msg.indices_in_this_network_frame.n_chunks += 1
            is_final = int(ws["websocket.fin"])
            assert is_final in {0, 1}, (self.frame_nb, ws_ix)
            if is_final:
                cur_msg.finalized_in_this_network_frame = True
                finalized_messages.append(cur_msg)
                cur_msg = None
            else:
                # if None: continued from another network frame
                # but initial message should be continuable (checked later)
                assert cur_msg.opcode is None or cur_msg.opcode in CONTINUABLE_OPCODES, (self.frame_nb, ws_ix)
        if cur_msg is not None:
            LOGGER.debug(f"Frame #{self.frame_nb}: last websocket message is incomplete in frame")
            # this message is not "finalized" per se, but no more data in this network frame,
            # thus we do NOT set the the `finalized_in_this_network_frame` flag for this one
            finalized_messages.append(cur_msg)
        return finalized_messages

    @cached_property
    def closure_messages(self) -> list[WebSocketMessageInNetworkFramePossiblyIncomplete]:
        return [msg for msg in self.websocket_messages if msg.opcode is WebSocketOpcode.close]

    @cached_property
    def has_closure(self) -> bool:
        return bool(self.closure_messages)

    @cached_property
    def non_closure_messages(self) -> list[WebSocketMessageInNetworkFramePossiblyIncomplete]:
        """<!> not necessarily finalized in this network frame"""
        return [msg for msg in self.websocket_messages if msg.opcode is not WebSocketOpcode.close]

    @cached_property
    def has_non_closure(self) -> bool:
        return bool(self.non_closure_messages)

    def _update_messages_indices_for_continuable_opcodes(self) -> None:
        """
        We can NOT perform this before determining the actual type of messages continued from previous network frame(s)
        """
        txt_ix = 0
        bin_ix = 0
        for msg in self.websocket_messages:
            if not msg.finalized_in_this_network_frame:
                continue
            match msg.opcode:
                case WebSocketOpcode.text:
                    msg.indices_in_this_network_frame.message_index_for_opcode = txt_ix
                    txt_ix += 1
                case WebSocketOpcode.binary:
                    msg.indices_in_this_network_frame.message_index_for_opcode = bin_ix
                    bin_ix += 1
                case None:
                    raise ValueError(f"Frame #{self.frame_nb}: missing actual opcode for continued {msg!r}")
                case _:
                    continue
        self._has_all_metadata = True

    def fill_opcode_of_continued_messages(
        self, last_msg_from_previous_frame: WebSocketMessageInNetworkFramePossiblyIncomplete | None, /
    ) -> WebSocketMessageInNetworkFramePossiblyIncomplete:
        if last_msg_from_previous_frame is not None:
            assert last_msg_from_previous_frame.opcode is not None
        for msg in self.websocket_messages:
            if msg.opcode is None:
                assert last_msg_from_previous_frame is not None, self.frame_nb
                assert last_msg_from_previous_frame.opcode in CONTINUABLE_OPCODES, (
                    self.frame_nb,
                    last_msg_from_previous_frame,
                )
                msg.opcode = last_msg_from_previous_frame.opcode
                last_msg_from_previous_frame = None
        self._update_messages_indices_for_continuable_opcodes()
        return self.websocket_messages[-1]

    def _get_finalized_messages_for_opcode(
        self, opcode: WebSocketOpcode
    ) -> list[WebSocketMessageInNetworkFramePossiblyIncomplete]:
        assert self._has_all_metadata, self.frame_nb
        return [msg for msg in self.websocket_messages if msg.opcode is opcode and msg.finalized_in_this_network_frame]

    @cached_property
    def finalized_text_messages(self) -> list[WebSocketMessageInNetworkFramePossiblyIncomplete]:
        return self._get_finalized_messages_for_opcode(WebSocketOpcode.text)

    @cached_property
    def finalized_binary_messages(self) -> list[WebSocketMessageInNetworkFramePossiblyIncomplete]:
        return self._get_finalized_messages_for_opcode(WebSocketOpcode.binary)

    def _try_to_manually_recover_ws_data(self, *, binary: bool) -> list[TsharkRaw] | None:
        if binary:
            # Ref: <https://gitlab.com/wireshark/wireshark/-/blob/master/epan/packet.c>
            # Nota: no such cases has been encountered so far
            LOGGER.debug(
                "-> tshark dissection logic for fragmented BINARY messages does NOT seem to permit"
                " an easy recovery of payloads, unlike for text messages"
            )
            return None
        data_key = _get_ws_data_key(binary=binary)
        finalized_messages_for_opcode = self.finalized_binary_messages if binary else self.finalized_text_messages
        try:
            raw_text_payloads = [
                msg.get_raw_text_payload_manually(self.websocket_layers) for msg in finalized_messages_for_opcode
            ]
        except Exception as e:
            e.add_note(f"Frame #{self.frame_nb}")
            raise
        # we change layers in-place to avoid re-doing this recovery for future messages of this frame
        self.layers[data_key] = [{}] * len(finalized_messages_for_opcode)
        self.layers[f"{data_key}_raw"] = raw_text_payloads
        return raw_text_payloads

    def _get_regular_data(self, message_ix_for_opcode: int | None, *, binary: bool) -> str | None:
        assert message_ix_for_opcode is not None, self.frame_nb
        data_key = _get_ws_data_key(binary=binary)
        data_raw = self.layers[f"{data_key}_raw"]
        n_finalized_messages_for_opcode = len(
            self.finalized_binary_messages if binary else self.finalized_text_messages
        )
        if n_finalized_messages_for_opcode > 1:  # list of list
            expected_data_type_signature = f"list[{n_finalized_messages_for_opcode}]"
            actual_data_type_signature = (
                f"list[{len(data_raw)}]"
                if isinstance(self.layers[data_key], list)  # *-raw is always a list
                else "dict"
            )
            if actual_data_type_signature != expected_data_type_signature:  # happens (tshark issue)
                if message_ix_for_opcode != 0:  # could not be fixed previously...
                    return None  # unrecoverable error
                opcode_lbl = "binary" if binary else "text"
                LOGGER.warning(
                    f"Frame #{self.frame_nb}: {data_key} ({actual_data_type_signature}) is inconsistent"
                    f" with WebSocket {opcode_lbl} messages ({expected_data_type_signature})"
                    "\n-> trying an alternate way to recover reassembled payloads..."
                )
                if not (data_raw := self._try_to_manually_recover_ws_data(binary=binary)):
                    LOGGER.error("-> impossible to recover payloads, falling back to null for data field")
                    return None  # unrecoverable error
                LOGGER.warning(f"-> successfully recovered {n_finalized_messages_for_opcode} {opcode_lbl} payloads")
            data_raw = data_raw[message_ix_for_opcode]
        else:
            assert message_ix_for_opcode == 0, (self.frame_nb, message_ix_for_opcode, binary)
        bytes_for_ix = get_tshark_bytes_from_raw(data_raw)
        return b64encode(bytes_for_ix).decode("ascii") if binary else bytes_for_ix.decode()

    def _get_ping_pong_data(self, msg: WebSocketMessageInNetworkFramePossiblyIncomplete, *, ping: bool) -> str:
        ws_layers = msg.get_subset_of_websocket_layers(self.websocket_layers)
        assert len(ws_layers) == 1, self.frame_nb
        ws_payload_tree, _ = _get_websocket_payload_tree(ws_layers[0], msg=msg, frame_nb=self.frame_nb)
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
        closure_msg = self.closure_messages[0]
        closure_msg_ws_layers = closure_msg.get_subset_of_websocket_layers(self.websocket_layers)
        assert len(closure_msg_ws_layers) == 1, (self.frame_nb, closure_msg)
        ws_payload, tree_suffix = _get_websocket_payload_tree(
            closure_msg_ws_layers[0], msg=closure_msg, frame_nb=self.frame_nb
        )
        closure_payload = ws_payload.get(f"websocket.payload.close{tree_suffix}", {})
        optional_code = closure_payload.get("websocket.payload.close.status_code")
        return {
            "type": self.get_direction(src_dst_req),
            "code": int(optional_code) if optional_code is not None else None,
            "reason": closure_payload.get("websocket.payload.close.reason"),
            "time": self.timestamp,
        }

    def _regular_to_har(
        self,
        msg: WebSocketMessageInNetworkFramePossiblyIncomplete,
        typ: WebSocketDirection,
        /,
    ) -> dict[str, Any]:
        assert msg.finalized_in_this_network_frame, (self.frame_nb, msg)
        data: str | None
        match msg.opcode:
            case WebSocketOpcode.text:
                data = self._get_regular_data(
                    msg.indices_in_this_network_frame.message_index_for_opcode,
                    binary=False,
                )
            case WebSocketOpcode.binary:
                data = self._get_regular_data(
                    msg.indices_in_this_network_frame.message_index_for_opcode,
                    binary=True,
                )
            case WebSocketOpcode.ping:
                assert typ == "send", (self.frame_nb, msg)
                data = self._get_ping_pong_data(msg, ping=True)
            case WebSocketOpcode.pong:
                assert typ == "receive", (self.frame_nb, msg)
                data = self._get_ping_pong_data(msg, ping=False)
            case _:
                raise ValueError(f"Frame #{self.frame_nb}: unexpected {msg!r}")
        return {
            "type": typ,
            "opcode": int(msg.opcode),
            "data": data,
            "time": self.timestamp,  # <!> timestamp of final chunk (i.e. of frame when message got finalized)
        }

    def regulars_to_har(self, src_dst_req: tuple[IPPort, IPPort], /) -> list[dict[str, Any]]:
        typ = self.get_direction(src_dst_req)
        return [
            self._regular_to_har(msg, typ) for msg in self.non_closure_messages if msg.finalized_in_this_network_frame
        ]

    def sorting_key(self) -> float:
        return self.timestamp  # same for all messages within this instance


@dataclass(frozen=False)
class WebSocketConversation:
    src_dst_req: Final[tuple[IPPort, IPPort]]  # type: ignore[misc]
    all_messages: Final[list[WebSocketMessagesInNetworkFramePossiblyIncomplete]] = field(default_factory=list)
    is_closed: bool = False

    def push(self, messages: WebSocketMessagesInNetworkFramePossiblyIncomplete) -> None:
        if messages.has_non_closure:
            assert not self.is_closed, messages.frame_nb
        if messages.has_closure:
            self.is_closed = True
        self.all_messages.append(messages)

    def _update_info_of_continued_messages(self) -> None:
        last_msg: WebSocketMessageInNetworkFramePossiblyIncomplete | None = None
        for msgs in self.all_messages:
            last_msg = msgs.fill_opcode_of_continued_messages(last_msg)
        if last_msg is not None and not last_msg.finalized_in_this_network_frame:
            LOGGER.warning(f"Frame #{self.all_messages[-1].frame_nb}: latest websocket message is incomplete")

    def to_har(self) -> dict[str, Any]:
        """Ref: HTTP Toolkit schema"""
        self._update_info_of_continued_messages()
        all_messages_sorted = sorted(
            self.all_messages,
            key=WebSocketMessagesInNetworkFramePossiblyIncomplete.sorting_key,
        )
        d: dict[str, Any] = {
            "_resourceType": "websocket",
            "_webSocketMessages": sum(
                (frames.regulars_to_har(self.src_dst_req) for frames in all_messages_sorted),
                [],
            ),
        }
        if self.is_closed:
            # we only retain the FIRST closure event (as in HTTP Toolkit)
            first_with_closure = next(iter(msgs for msgs in all_messages_sorted if msgs.has_closure))
            d["_webSocketClose"] = first_with_closure.closure_to_har(self.src_dst_req)
        return d
