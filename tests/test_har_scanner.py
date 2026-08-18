import base64
import json

from pcapng_utils.pii.har_scanner import HarPiiScanner


def _sample_har() -> dict:
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "http://example.test/users/13800138000?email=demo%40example.com",
                        "headers": [{"name": "X-Contact", "value": "13800138000"}],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({"profile": {"email": "user@example.cn"}}),
                        },
                    },
                    "response": {
                        "headers": [],
                        "content": {
                            "mimeType": "text/plain",
                            "text": "call 13912345678",
                        },
                    },
                }
            ]
        }
    }


def test_scans_structured_har_fields_and_builds_summary() -> None:
    report = HarPiiScanner().scan(_sample_har(), source_name="sample.har")

    assert report["summary"] == {
        "total_entries": 1,
        "entries_with_pii": 1,
        "finding_count": 5,
        "unique_finding_count": 4,
        "by_entity": {"CN_PHONE_NUMBER": 3, "EMAIL_ADDRESS": 2},
        "unique_by_entity": {"CN_PHONE_NUMBER": 2, "EMAIL_ADDRESS": 2},
        "by_severity": {"high": 3, "medium": 2},
    }
    assert {item["location"] for item in report["findings"]} == {
        "request.url.path",
        "request.query[0]",
        "request.headers.X-Contact",
        "request.body.profile.email",
        "response.body",
    }


def test_report_contains_masked_values_not_raw_pii() -> None:
    serialized = json.dumps(HarPiiScanner().scan(_sample_har()), ensure_ascii=False)

    for raw_value in ("13800138000", "13912345678", "demo@example.com", "user@example.cn"):
        assert raw_value not in serialized
    assert "fingerprint" not in serialized
    assert "138****8000" in serialized
    assert "de***@example.com" in serialized


def test_scans_base64_response_and_websocket_messages() -> None:
    encoded_body = base64.b64encode(b"email=body@example.com").decode("ascii")
    har = {
        "log": {
            "entries": [
                {
                    "request": {"method": "GET", "url": "ws://example.test/socket"},
                    "response": {
                        "content": {
                            "mimeType": "text/plain",
                            "encoding": "base64",
                            "text": encoded_body,
                        }
                    },
                    "_webSocketMessages": [
                        {"type": "send", "opcode": 1, "data": "phone=13712345678"}
                    ],
                }
            ]
        }
    }

    report = HarPiiScanner().scan(har)

    assert report["summary"]["finding_count"] == 2
    assert report["summary"]["unique_finding_count"] == 2
    assert {item["location"] for item in report["findings"]} == {
        "response.body",
        "websocket.messages[0]",
    }
    serialized = json.dumps(report)
    assert "body@example.com" not in serialized
    assert "13712345678" not in serialized
