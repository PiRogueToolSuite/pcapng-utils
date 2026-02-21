import binascii
import json
from datetime import datetime, timezone
from hashlib import sha1
from collections.abc import Sequence, Mapping
from typing import Optional, Any

from .types import DictLayers, TsharkRaw


def get_layers_mapping(traffic: Sequence[DictLayers]) -> Mapping[int, DictLayers]:
    """
    Get mapping of layers by frame number (once for all).
    """
    mapping: dict[int, DictLayers] = {}
    for layers in traffic:
        frame_number = int(layers.get("frame", {}).get("frame.number", -1))
        if frame_number >= 0:
            assert frame_number not in mapping, frame_number
            mapping[frame_number] = layers
    return mapping


def get_community_id(layers: DictLayers) -> str:
    """
    Get community ID hash from tshark layers (compatible with multiple tshark versions)
    """
    POSSIBLE_COMMUNITY_ID_KEYS = ("communityid.hash", "communityid")
    for k in POSSIBLE_COMMUNITY_ID_KEYS:
        if k in layers:
            return layers[k]
    raise KeyError(f"Community ID not found: {list(layers)}")

def get_timestamp(layers: DictLayers) -> float:
    """
    Get frame timestamp (compatible with multiple tshark versions)
    """
    epoch = layers['frame']['frame.time_epoch']
    try:
        return datetime.fromisoformat(epoch).timestamp()  # new tshark versions
    except ValueError:
        return float(epoch)

def get_tshark_bytes_from_raw(r: Optional[TsharkRaw]) -> bytes:
    """
    Format of '*_raw' fields produced with '-x' flag: [hexa: str, *sizes: int]

    Sizes are 4 integers in tshark old versions and 5 integers in newer (>= v4.6)
    """
    if r is None:
        return b""
    assert isinstance(r, list) and len(r) in {5, 6}, r
    assert all(isinstance(i, int) for i in r[1:]), r
    hexa = r[0]
    assert isinstance(hexa, str) and hexa.isascii(), r
    return binascii.unhexlify(hexa)


def har_entry_with_common_fields(har_entry: dict[str, Any]) -> dict[str, Any]:
    """
    Return provided HAR entry together with common fields.

    In particular, we add the non-standard `_sha1Id` field that serves both as entry identifier +
    easy changes-tracker across different releases of this software.
    """
    to_hash = json.dumps(
        har_entry, allow_nan=False, ensure_ascii=True, indent=0, sort_keys=True
    ).encode("ascii")
    sha1id = sha1(to_hash).hexdigest()
    timestamp_iso = datetime.fromtimestamp(
        har_entry["_timestamp"], timezone.utc
    ).isoformat()
    timing_tot = sum(dur for dur in har_entry["timings"].values() if dur != -1)
    return {
        "_sha1Id": sha1id,
        "startedDateTime": timestamp_iso,
        **har_entry,
        "time": round(timing_tot, 2),
        "cache": {},  # not handled by this software
    }
