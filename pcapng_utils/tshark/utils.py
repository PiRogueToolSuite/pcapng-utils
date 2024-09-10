import re
import base64
import binascii
from dataclasses import dataclass, field
from typing import Sequence, Mapping, Optional, Self, Any

DictLayers = Mapping[str, Any]


def get_layers_mapping(traffic: Sequence[DictLayers]) -> Mapping[int, DictLayers]:
    """Get mapping of layers by frame number (once for all)."""
    mapping: dict[int, DictLayers] = {}
    for layers in traffic:
        frame_number = int(layers.get('frame', {}).get('frame.number', -1))
        if frame_number >= 0:
            assert frame_number not in mapping, frame_number
            mapping[frame_number] = layers
    return mapping


def _get_tshark_bytes_from_hex(s: str) -> Optional[bytes]:
    if not s or not s.isascii():  # fail fast
        return None
    rx_with_colons = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2})*$")
    rx_no_colons = re.compile(r"^([0-9a-f]{2})+$")  # from "_raw" fields produced with '-x' flag
    is_tshark_hex = rx_with_colons.match(s) or rx_no_colons.match(s)
    return binascii.unhexlify(s.replace(':', '')) if is_tshark_hex else None


@dataclass(frozen=True)
class Payload:
    """Representation of either base64-encoded bytes or plain-text UTF8 string (useful for HAR export)."""

    bytes_: bytes = field(default=b'', repr=False)
    is_printable: bool = True

    @property
    def size(self) -> int:
        return len(self.bytes_)  # <!> len('€') == 1 != len('€'.encode()) == 3

    @classmethod
    def from_str(cls, s: str, *, encoding: str = "utf-8") -> Self:
        """Constructor from string (UTF8 by default)."""
        assert s.isprintable(), s
        return cls(s.encode(encoding), True)

    @classmethod
    def from_bytes(cls, b: bytes) -> Self:
        """Constructor from bytes."""
        return cls(b, False)

    @classmethod
    def concat(cls, *payloads: Self) -> Self:
        """Concatenate all payloads in order."""
        concat_bytes = b''.join(p.bytes_ for p in payloads)  # can't use `sum` here
        return cls(concat_bytes, all(p.is_printable for p in payloads))

    @classmethod
    def from_unsure_tshark_data(cls, data: str, *, encoding: str = "utf-8") -> Self:
        """New payload from either plain-text printable string or HEX string in tshark format."""
        data_bytes = _get_tshark_bytes_from_hex(data)
        if data_bytes is None:
            return cls.from_str(data, encoding=encoding)
        else:
            # try this in case these bytes represent a printable string
            try:
                return cls.from_str(data_bytes.decode(encoding), encoding=encoding)
            except:
                pass
        return cls.from_bytes(data_bytes)

    def to_har_dict(self) -> dict[str, Any]:
        """Export with HAR syntax."""
        if self.is_printable:
            return {
                "size": self.size,
                "text": self.bytes_.decode(),
            }
        return {
            "size": self.size,
            "text": base64.b64encode(self.bytes_).decode("ascii"),
            "encoding": "base64",
        }
