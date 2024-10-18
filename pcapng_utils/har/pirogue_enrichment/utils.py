import base64
from re import sub


def to_camel_case(s):
    s = sub(r"(_|-)+", " ", s).title().replace(" ", "")
    return "".join([s[0].lower(), s[1:]])


def prefix_string_camel_case(key: str, prefix: str = "_"):
    return f"{prefix}{to_camel_case(key)}"


def clean_prefixed_ip_address(ip_address: str) -> str:
    if ip_address.startswith("::ffff:") and ip_address.count(".") == 3:
        return ip_address.replace("::ffff:", "")
    return ip_address


def base64_to_hex(base64_encoded_data: str, validate: bool = True) -> str:
    """Convert a base64 encoded string to a hexadecimal string"""
    if not base64_encoded_data:
        return ''
    # Try to decode the base64 encoded data
    try:
        binary_payload = base64.b64decode(base64_encoded_data, validate=validate)
        return binary_payload.hex()
    except Exception:
        return ''
