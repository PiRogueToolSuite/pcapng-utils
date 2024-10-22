from collections.abc import Sequence, Mapping
from typing import Protocol, Any

TsharkRaw = list[str | int]
DictPacket = Mapping[str, Any]
DictLayers = Mapping[str, Any]
HarEntry = dict[str, Any]
NameValueDict = Mapping[str, str]


class ParsedTrafficProtocol(Protocol):
    def __init__(self, traffic: Sequence[DictLayers]) -> None: ...

    def get_har_entries(self) -> list[HarEntry]: ...
