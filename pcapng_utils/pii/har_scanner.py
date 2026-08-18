"""Extract application text from HAR and produce a masked PII report."""

from __future__ import annotations

import base64
import binascii
import html
import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qsl, unquote, urlsplit

from .analyzer import PiiAnalyzer


@dataclass(frozen=True)
class TextTarget:
    direction: str
    location: str
    text: str


class HarPiiScanner:
    """Scan decoded HAR request, response and WebSocket application fields."""

    def __init__(self, analyzer: PiiAnalyzer | None = None) -> None:
        self.analyzer = analyzer or PiiAnalyzer()

    def scan_file(
        self,
        input_path: Path,
        *,
        source_name: str | None = None,
        source_format: str = "har",
    ) -> dict[str, Any]:
        with input_path.open("r", encoding="utf-8") as handle:
            har = json.load(handle)
        return self.scan(
            har,
            source_name=source_name or input_path.name,
            source_format=source_format,
        )

    def scan(
        self,
        har: dict[str, Any],
        source_name: str | None = None,
        source_format: str = "har",
    ) -> dict[str, Any]:
        entries = har.get("log", {}).get("entries", [])
        if not isinstance(entries, list):
            raise ValueError("Invalid HAR: log.entries must be a list")

        findings: list[dict[str, Any]] = []
        entries_with_pii: set[int] = set()
        unique_values: set[tuple[str, str]] = set()
        unique_values_by_entity: dict[str, set[str]] = {}

        for entry_index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            request = entry.get("request", {})
            request_url = request.get("url", "") if isinstance(request, dict) else ""
            split_url = urlsplit(request_url)
            method = request.get("method") if isinstance(request, dict) else None

            for target in self._iter_entry_targets(entry):
                for detection in self.analyzer.analyze(target.text):
                    entries_with_pii.add(entry_index)
                    unique_values.add((detection.entity_type, detection.value_fingerprint))
                    unique_values_by_entity.setdefault(detection.entity_type, set()).add(
                        detection.value_fingerprint
                    )
                    finding = {
                        "entity_type": detection.entity_type,
                        "start": detection.start,
                        "end": detection.end,
                        "score": detection.score,
                        "masked_value": detection.masked_value,
                        "severity": detection.severity,
                        "entry_index": entry_index,
                        "direction": target.direction,
                        "location": target.location,
                        "request_method": method,
                        "destination_host": split_url.hostname,
                        "request_path": self.analyzer.redact(unquote(split_url.path or "/")),
                    }
                    findings.append(finding)

        entity_counts = Counter(item["entity_type"] for item in findings)
        severity_counts = Counter(item["severity"] for item in findings)
        return {
            "report_version": "1.1",
            "generated_at": datetime.now(UTC).isoformat(),
            "source": source_name,
            "source_format": source_format,
            "summary": {
                "total_entries": len(entries),
                "entries_with_pii": len(entries_with_pii),
                "finding_count": len(findings),
                "unique_finding_count": len(unique_values),
                "by_entity": dict(sorted(entity_counts.items())),
                "unique_by_entity": {
                    entity_type: len(values)
                    for entity_type, values in sorted(unique_values_by_entity.items())
                },
                "by_severity": dict(sorted(severity_counts.items())),
            },
            "findings": findings,
        }

    def _iter_entry_targets(self, entry: dict[str, Any]) -> Iterator[TextTarget]:
        request = entry.get("request", {})
        response = entry.get("response", {})
        if isinstance(request, dict):
            yield from self._iter_url(request.get("url"))
            yield from self._iter_name_value_list(request.get("headers"), "request", "headers")
            yield from self._iter_name_value_list(request.get("cookies"), "request", "cookies")
            post_data = request.get("postData")
            if isinstance(post_data, dict):
                text = self._decode_text(post_data)
                if text is not None:
                    yield from self._iter_body(text, post_data.get("mimeType", ""), "request", "body")

        if isinstance(response, dict):
            yield from self._iter_name_value_list(response.get("headers"), "response", "headers")
            yield from self._iter_name_value_list(response.get("cookies"), "response", "cookies")
            content = response.get("content")
            if isinstance(content, dict):
                text = self._decode_text(content)
                if text is not None:
                    yield from self._iter_body(text, content.get("mimeType", ""), "response", "body")

        messages = entry.get("_webSocketMessages")
        if isinstance(messages, list):
            for index, message in enumerate(messages):
                if not isinstance(message, dict) or not isinstance(message.get("data"), str):
                    continue
                direction = "request" if message.get("type") == "send" else "response"
                yield TextTarget(direction, f"websocket.messages[{index}]", message["data"])

    @staticmethod
    def _iter_url(url: Any) -> Iterator[TextTarget]:
        if not isinstance(url, str):
            return
        parsed = urlsplit(url)
        if parsed.path:
            yield TextTarget("request", "request.url.path", unquote(parsed.path))
        for index, (_, value) in enumerate(parse_qsl(parsed.query, keep_blank_values=True)):
            yield TextTarget("request", f"request.query[{index}]", value)

    @staticmethod
    def _iter_name_value_list(items: Any, direction: str, kind: str) -> Iterator[TextTarget]:
        if not isinstance(items, list):
            return
        for index, item in enumerate(items):
            if not isinstance(item, dict) or not isinstance(item.get("value"), str):
                continue
            name = item.get("name", "")
            compact_name = name.replace("-", "") if isinstance(name, str) else ""
            safe_name = (
                name
                if isinstance(name, str)
                and 0 < len(name) <= 40
                and name[0].isalpha()
                and compact_name.isalnum()
                else str(index)
            )
            yield TextTarget(direction, f"{direction}.{kind}.{safe_name}", item["value"])

    def _iter_body(
        self, text: str, mime_type: Any, direction: str, base_location: str
    ) -> Iterator[TextTarget]:
        mime = mime_type.lower() if isinstance(mime_type, str) else ""
        stripped = text.lstrip()
        if "json" in mime or stripped.startswith(("{", "[")):
            try:
                value = json.loads(text)
            except json.JSONDecodeError:
                pass
            else:
                yield from self._iter_json_scalars(value, direction, base_location)
                return

        if "application/x-www-form-urlencoded" in mime:
            for index, (_, value) in enumerate(parse_qsl(text, keep_blank_values=True)):
                yield TextTarget(direction, f"{direction}.{base_location}.form[{index}]", value)
            return

        yield TextTarget(direction, f"{direction}.{base_location}", html.unescape(text))

    def _iter_json_scalars(
        self, value: Any, direction: str, location: str
    ) -> Iterator[TextTarget]:
        if isinstance(value, dict):
            for index, (key, child) in enumerate(value.items()):
                safe_key = self._safe_json_key(key, index)
                yield from self._iter_json_scalars(child, direction, f"{location}.{safe_key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                yield from self._iter_json_scalars(child, direction, f"{location}[{index}]")
        elif isinstance(value, str):
            yield TextTarget(direction, f"{direction}.{location}", value)
        elif isinstance(value, int) and not isinstance(value, bool):
            yield TextTarget(direction, f"{direction}.{location}", str(value))

    @staticmethod
    def _safe_json_key(key: Any, index: int) -> str:
        if isinstance(key, str) and key and len(key) <= 40:
            compact = key.replace("_", "").replace("-", "")
            if compact.isalnum() and not compact.isdigit():
                return key
        return f"field[{index}]"

    @staticmethod
    def _decode_text(container: dict[str, Any]) -> str | None:
        text = container.get("text")
        if not isinstance(text, str):
            return None
        if container.get("encoding") != "base64":
            return text
        try:
            return base64.b64decode(text, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None
