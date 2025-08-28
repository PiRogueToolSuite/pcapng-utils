import base64
from re import sub
from typing import TypeVar


def to_camel_case(s: str) -> str:
    s = sub(r"(_|-)+", " ", s).title().replace(" ", "")
    return "".join([s[0].lower(), s[1:]])


def _to_camel_case_after_prefix(key: str, prefix: str) -> str:
    return f"{prefix}{to_camel_case(key)}"


def clean_prefixed_ip_address(ip_address: str) -> str:
    if ip_address.startswith("::ffff:") and ip_address.count(".") == 3:
        return ip_address.replace("::ffff:", "")
    return ip_address


_T = TypeVar("_T", dict, list, str)


def keys_to_camel_case(obj: _T, *, prefix: str = "") -> _T:
    """Recursively rename all keys of dictionaries within object with camel case (optionally prefixed)."""
    if isinstance(obj, dict):
        return {
            _to_camel_case_after_prefix(k, prefix): keys_to_camel_case(v, prefix=prefix)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [keys_to_camel_case(k, prefix=prefix) for k in obj]
    return obj


def robust_b64decode(b64_str: str, *, altchars: str | None = None) -> bytes:
    """Robustly decode some base64 data (standard, URL-safe, fixed width with new lines, without padding, ...)"""
    if not b64_str:
        return b""
    b64 = b64_str.encode("ascii")
    b64 = b64.replace(b"\n", b"")  # account for fixed-width base64
    if altchars is None:
        if b"-" in b64 or b"_" in b64:
            altchars = "-_"  # URL-safe base64
        # default with altchars=None is '+/' (standard base64)
    if not b64.endswith(b"="):
        padding = b"=" * (-len(b64) % 4)
        b64 += padding
    return base64.b64decode(b64, altchars=altchars, validate=True)
