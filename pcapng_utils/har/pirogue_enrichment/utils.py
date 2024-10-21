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


def base64_to_hex(base64_encoded_data: str, *, validate: bool = True) -> str:
    """Convert a base64 encoded string to a hexadecimal string"""
    return base64.b64decode(base64_encoded_data, validate=validate).hex()


_T = TypeVar('_T', dict, list, str)


def keys_to_camel_case(obj: _T, *, prefix: str = '') -> _T:
    """Recursively rename all keys of dictionaries within object with camel case (optionally prefixed)."""
    if isinstance(obj, dict):
        return {
            _to_camel_case_after_prefix(k, prefix): keys_to_camel_case(v, prefix=prefix)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [keys_to_camel_case(k, prefix=prefix) for k in obj]
    return obj
