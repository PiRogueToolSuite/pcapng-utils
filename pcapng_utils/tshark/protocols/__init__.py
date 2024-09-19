from typing import Sequence

from .http1 import Http1Traffic
from .http2 import Http2Traffic
from ..types import ParsedTrafficProtocol

PROTOCOLS: Sequence[type[ParsedTrafficProtocol]] = [Http1Traffic, Http2Traffic]

__all__ = ["PROTOCOLS", "Http1Traffic", "Http2Traffic"]
