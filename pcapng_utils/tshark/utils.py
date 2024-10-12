import base64
import binascii
from dataclasses import dataclass
from hashlib import sha1
from typing import Sequence, Mapping, Optional, Self, Any

from .types import DictLayers, TsharkRaw

ALLOWED_NON_PRINTABLE_CHARS = str.maketrans('', '', '\t\n\r')


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


@dataclass(frozen=True, repr=False)
class Payload:
    """Representation of either bytes, possibly representing UTF8 plain-text (useful for HAR export)."""

    bytes_: bytes = b''

    @property
    def size(self) -> int:
        return len(self.bytes_)  # <!> len('€') == 1 != len('€'.encode()) == 3

    def __bool__(self) -> bool:
        return bool(self.bytes_)

    def __repr__(self) -> str:
        if not self:
            return "Payload(size=0)"
        return f"Payload(size={self.size}, sha1={sha1(self.bytes_).hexdigest()})"

    @classmethod
    def concat(cls, *payloads: Self) -> Self:
        """Concatenate all payloads in order."""
        concat_bytes = b''.join(p.bytes_ for p in payloads)  # can't use `sum` here
        return cls(concat_bytes)

    @classmethod
    def from_tshark_raw(cls, data: Optional[TsharkRaw]) -> Self:
        """New payload from special tshark '*_raw' field"""
        return cls(get_tshark_bytes_from_raw(data))

    def to_har_dict(self) -> dict[str, Any]:
        """Export with HAR syntax."""
        try:
            plain_txt = self.bytes_.decode()
            assert plain_txt.translate(ALLOWED_NON_PRINTABLE_CHARS).isprintable()
            return {
                "size": self.size,
                "text": plain_txt,
            }
        except:
            pass
        return {
            "size": self.size,
            "text": base64.b64encode(self.bytes_).decode("ascii"),
            "encoding": "base64",
        }
