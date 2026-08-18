"""Lightweight Presidio recognizers for common Chinese PII."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256

from presidio_analyzer import Pattern, PatternRecognizer

CN_PHONE_NUMBER = "CN_PHONE_NUMBER"
CN_ID_NUMBER = "CN_ID_NUMBER"
EMAIL_ADDRESS = "EMAIL_ADDRESS"


class ChinaIdRecognizer(PatternRecognizer):
    """Recognize 18-digit Chinese resident ID candidates with checksum validation."""

    _WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    _CHECK_CODES = "10X98765432"

    def __init__(self) -> None:
        super().__init__(
            supported_entity=CN_ID_NUMBER,
            supported_language="zh",
            name="Chinese Resident ID Recognizer",
            patterns=[
                Pattern(
                    name="18-digit Chinese resident ID",
                    regex=(
                        r"(?<!\d)\d{6}(?:18|19|20)\d{2}"
                        r"(?:0[1-9]|1[0-2])"
                        r"(?:0[1-9]|[12]\d|3[01])"
                        r"\d{3}[\dXx](?!\d)"
                    ),
                    score=0.7,
                )
            ],
        )

    def validate_result(self, pattern_text: str) -> bool:
        value = pattern_text.upper()
        if len(value) != 18 or not value[:17].isdigit():
            return False

        try:
            datetime.strptime(value[6:14], "%Y%m%d")
        except ValueError:
            return False

        checksum_index = sum(
            int(digit) * weight for digit, weight in zip(value[:17], self._WEIGHTS, strict=True)
        ) % 11
        return value[-1] == self._CHECK_CODES[checksum_index]


@dataclass(frozen=True)
class PiiDetection:
    """A PII match whose raw value remains confined to the scanned text."""

    entity_type: str
    start: int
    end: int
    score: float
    masked_value: str
    severity: str
    value_fingerprint: str


class PiiAnalyzer:
    """Run deterministic Presidio recognizers without loading an NLP model."""

    _SEVERITY = {
        CN_ID_NUMBER: "critical",
        CN_PHONE_NUMBER: "high",
        EMAIL_ADDRESS: "medium",
    }

    def __init__(self) -> None:
        self._recognizers: tuple[PatternRecognizer, ...] = (
            PatternRecognizer(
                supported_entity=CN_PHONE_NUMBER,
                supported_language="zh",
                name="Chinese Mobile Phone Recognizer",
                patterns=[
                    Pattern(
                        name="mainland China mobile number",
                        regex=r"(?<!\d)1[3-9]\d{9}(?!\d)",
                        score=0.85,
                    )
                ],
            ),
            PatternRecognizer(
                supported_entity=EMAIL_ADDRESS,
                supported_language="zh",
                name="Email Address Recognizer",
                patterns=[
                    Pattern(
                        name="email address",
                        regex=(
                            r"(?<![\w.+-])"
                            r"[A-Z0-9.!#$%'*+/?^_`{|}~-]+@"
                            r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
                            r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+"
                            r"(?![\w.-])"
                        ),
                        score=0.9,
                    )
                ],
            ),
            ChinaIdRecognizer(),
        )

    def analyze(self, text: str) -> list[PiiDetection]:
        """Return sorted, de-duplicated detections without exposing raw matches."""
        detections: list[PiiDetection] = []
        seen: set[tuple[str, int, int]] = set()

        for recognizer in self._recognizers:
            results = recognizer.analyze(
                text=text,
                entities=recognizer.supported_entities,
                nlp_artifacts=None,
            )
            for result in results:
                identity = (result.entity_type, result.start, result.end)
                if identity in seen:
                    continue
                seen.add(identity)
                raw_value = text[result.start : result.end]
                detections.append(
                    PiiDetection(
                        entity_type=result.entity_type,
                        start=result.start,
                        end=result.end,
                        score=round(result.score, 3),
                        masked_value=self.mask(result.entity_type, raw_value),
                        severity=self._SEVERITY[result.entity_type],
                        value_fingerprint=self.fingerprint(result.entity_type, raw_value),
                    )
                )

        return sorted(detections, key=lambda item: (item.start, item.end, item.entity_type))

    def redact(self, text: str) -> str:
        """Replace supported PII in text with entity-specific masked values."""
        redacted = text
        for detection in reversed(self.analyze(text)):
            redacted = redacted[: detection.start] + detection.masked_value + redacted[detection.end :]
        return redacted

    @staticmethod
    def fingerprint(entity_type: str, value: str) -> str:
        """Create an in-memory-only key for counting unique matched values."""
        normalized = value.strip()
        if entity_type == EMAIL_ADDRESS:
            normalized = normalized.casefold()
        elif entity_type == CN_ID_NUMBER:
            normalized = normalized.upper()
        payload = f"{entity_type}\0{normalized}".encode("utf-8")
        return sha256(payload).hexdigest()

    @staticmethod
    def mask(entity_type: str, value: str) -> str:
        """Mask a matched value while preserving a small recognition hint."""
        if entity_type == CN_PHONE_NUMBER and len(value) == 11:
            return f"{value[:3]}****{value[-4:]}"
        if entity_type == CN_ID_NUMBER and len(value) == 18:
            return f"{value[:3]}************{value[-3:]}"
        if entity_type == EMAIL_ADDRESS and "@" in value:
            local, domain = value.rsplit("@", 1)
            visible = local[:2] if len(local) > 1 else local[:1]
            return f"{visible}***@{domain}"
        return "***"
