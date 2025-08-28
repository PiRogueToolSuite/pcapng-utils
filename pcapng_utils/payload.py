import base64
from dataclasses import dataclass
from functools import cached_property
from hashlib import sha1
from typing import TypedDict, NotRequired, Literal, Self, Any

ALLOWED_NON_PRINTABLE_CHARS = str.maketrans("", "", "\t\n\r")


class HARPayloadDict(TypedDict):
    size: int
    text: str
    encoding: NotRequired[Literal["base64"]]


@dataclass(frozen=True, repr=False)
class Payload:
    """Representation of either bytes, possibly representing UTF8 plain-text (useful for HAR export)."""

    bytes_: bytes = b""

    @cached_property
    def size(self) -> int:
        return len(self.bytes_)  # <!> len('€') == 1 != len('€'.encode()) == 3

    @cached_property
    def sha1(self) -> str:
        return sha1(self.bytes_).hexdigest()

    def __bool__(self) -> bool:
        return bool(self.bytes_)

    def __repr__(self) -> str:
        if not self:
            return "Payload(size=0)"
        return f"Payload(size={self.size}, sha1={self.sha1})"

    @classmethod
    def concat(cls, *payloads: Self) -> Self:
        """Concatenate all payloads in order."""
        concat_bytes = b"".join(p.bytes_ for p in payloads)  # can't use `sum` here
        return cls(concat_bytes)

    def to_har_dict(self) -> HARPayloadDict:
        """Serialize content, with HAR formalism (cf. remarks in `update_har_request`)."""
        try:
            plain_txt = self.bytes_.decode()
            assert plain_txt.translate(ALLOWED_NON_PRINTABLE_CHARS).isprintable()
            return {
                "size": self.size,
                "text": plain_txt,
            }
        except Exception:  # noqa
            pass
        return {
            "size": self.size,
            "text": base64.b64encode(self.bytes_).decode("ascii"),
            "encoding": "base64",
        }

    def update_har_request(self, request_entry: dict[str, Any], mimetype: str) -> None:
        """Complete entry.request in-place

        In specs, `size` & `encoding` are not supported for `postData`,
        so we shall use the `httptoolkit` standard to store non-printable request data,
        in the dedicated `_content` field + `_requestBodyStatus: 'discarded:not-representable'`

        We remove any original request data keys prior to filling with new ones
        """
        # clean-up request entry first
        request_entry.pop("postData", None)
        request_entry.pop("_content", None)
        request_entry.pop("_requestBodyStatus", None)
        # fill with new data
        har_payload = self.to_har_dict()
        if "encoding" in har_payload:
            request_entry["_requestBodyStatus"] = "discarded:not-representable"
            request_entry["_content"] = {
                "mimeType": mimetype,  # addition to httptoolkit specs, for consistence
                **har_payload,
            }
        else:
            request_entry["postData"] = {
                "mimeType": mimetype,
                "params": [],  # mandatory in specs
                **har_payload,
                # size is not in specs...
                "_size": har_payload["size"],
            }
            del request_entry["postData"]["size"]

    def update_har_response(
        self, response_entry: dict[str, Any], mimetype: str
    ) -> None:
        """Complete entry.response in-place"""
        response_entry["content"] = {
            "mimeType": mimetype,
            **self.to_har_dict(),
        }
