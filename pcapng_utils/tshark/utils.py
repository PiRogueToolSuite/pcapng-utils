import binascii
from typing import Sequence, Mapping, Optional

from .types import DictLayers, TsharkRaw


def get_layers_mapping(traffic: Sequence[DictLayers]) -> Mapping[int, DictLayers]:
    """Get mapping of layers by frame number (once for all)."""
    mapping: dict[int, DictLayers] = {}
    for layers in traffic:
        frame_number = int(layers.get('frame', {}).get('frame.number', -1))
        if frame_number >= 0:
            assert frame_number not in mapping, frame_number
            mapping[frame_number] = layers
    return mapping


def get_tshark_bytes_from_raw(r: Optional[TsharkRaw]) -> bytes:
    """Format of '*_raw' fields produced with '-x' flag: [hexa: str, *sizes: int]"""
    if r is None:
        return b''
    assert isinstance(r, list) and len(r) == 5, r
    hexa = r[0]
    assert isinstance(hexa, str) and hexa.isascii(), hexa
    return binascii.unhexlify(hexa)
