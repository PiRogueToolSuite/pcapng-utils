from collections.abc import Sequence, Mapping
from datetime import datetime
from functools import cached_property
from typing import Protocol, Any

from .types import IPPort, HasLayers, DictLayers


def get_layers_mapping(traffic: Sequence[DictLayers]) -> Mapping[int, DictLayers]:
    """Get mapping of layers by frame number (once for all)"""
    mapping: dict[int, DictLayers] = {}
    for layers in traffic:
        frame_number = int(layers.get("frame", {}).get("frame.number", -1))
        if frame_number >= 0:
            assert frame_number not in mapping, frame_number
            mapping[frame_number] = layers
    return mapping


def get_protocols(layers: DictLayers) -> list[str]:
    """Get frame protocols"""
    return layers["frame"]["frame.protocols"].split(":")


def get_timestamp(layers: DictLayers) -> float:
    """Get frame timestamp (compatible with multiple tshark versions)"""
    epoch = layers["frame"]["frame.time_epoch"]
    try:
        return datetime.fromisoformat(epoch).timestamp()  # new tshark versions
    except ValueError:
        return float(epoch)  # older versions


class FrameMixin:

    @property
    def frame_nb(self: HasLayers) -> int:
        # useful for debugging with Wireshark
        return int(self.layers["frame"]["frame.number"])

    @property
    def timestamp(self: HasLayers) -> float:
        return get_timestamp(self.layers)


class HasSrcDstIpHostPort(Protocol):
    @property
    def src_ip(self) -> str: ...
    @property
    def src_host(self) -> str: ...
    @property
    def src_port(self) -> int: ...
    @property
    def dst_ip(self) -> str: ...
    @property
    def dst_host(self) -> str: ...
    @property
    def dst_port(self) -> int: ...


def get_har_communication(r: HasSrcDstIpHostPort, /) -> dict[str, Any]:
    return {
        "src": {
            "ip": r.src_ip,
            "host": r.src_host,
            "port": r.src_port,
        },
        "dst": {
            "ip": r.dst_ip,
            "host": r.dst_host,
            "port": r.dst_port,
        },
    }


def get_tcp_stream_id(layers: DictLayers) -> int:
    return int(layers["tcp"]["tcp.stream"])


class TCPIPMixin:

    @cached_property
    def ip_version_and_layer(self: HasLayers) -> tuple[str, dict[str, Any]]:
        ipv4 = "ip" in self.layers
        ipv6 = "ipv6" in self.layers
        assert ipv4 ^ ipv6, self
        ip_version_kw = "ipv6" if ipv6 else "ip"
        return ip_version_kw, self.layers[ip_version_kw]

    @property
    def src_ip(self) -> str:
        ipv, ip_layer = self.ip_version_and_layer  # type: ignore[misc]
        return ip_layer[f"{ipv}.src"]

    @property
    def src_host(self) -> str:
        ipv, ip_layer = self.ip_version_and_layer  # type: ignore[misc]
        return ip_layer[f"{ipv}.src_host"]  # with possibly resolved name

    @property
    def dst_ip(self) -> str:
        ipv, ip_layer = self.ip_version_and_layer  # type: ignore[misc]
        return ip_layer[f"{ipv}.dst"]

    @property
    def dst_host(self) -> str:
        ipv, ip_layer = self.ip_version_and_layer  # type: ignore[misc]
        return ip_layer[f"{ipv}.dst_host"]  # with possibly resolved name

    @property
    def src_port(self: HasLayers) -> int:
        return int(self.layers["tcp"]["tcp.srcport"])

    @property
    def dst_port(self: HasLayers) -> int:
        return int(self.layers["tcp"]["tcp.dstport"])

    @property
    def src_ip_port(self) -> IPPort:
        return (self.src_ip, self.src_port)  # type: ignore[misc]

    @property
    def dst_ip_port(self) -> IPPort:
        return (self.dst_ip, self.dst_port)  # type: ignore[misc]

    @property
    def tcp_stream_id(self: HasLayers) -> int:
        return get_tcp_stream_id(self.layers)

    @property
    def src_dst_ip_port(self) -> tuple[IPPort, IPPort]:
        return (self.src_ip_port, self.dst_ip_port)


def get_community_id(layers: DictLayers) -> str:
    """Get community ID from tshark layers (compatible with multiple tshark versions)"""
    POSSIBLE_COMMUNITY_ID_KEYS = ("communityid.hash", "communityid")
    for k in POSSIBLE_COMMUNITY_ID_KEYS:
        if k in layers:
            return layers[k]
    raise KeyError(f"Community ID not found: {list(layers)}")


class CommunityIDMixin:

    @property
    def community_id(self: HasLayers) -> str:
        return get_community_id(self.layers)
