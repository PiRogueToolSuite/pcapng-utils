from pcapng_utils.pii.analyzer import CN_ID_NUMBER, CN_PHONE_NUMBER, EMAIL_ADDRESS, PiiAnalyzer


def _valid_china_id(prefix: str = "11010119900101123") -> str:
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    check_codes = "10X98765432"
    checksum_index = sum(int(digit) * weight for digit, weight in zip(prefix, weights, strict=True)) % 11
    return prefix + check_codes[checksum_index]


def test_detects_and_masks_supported_entities() -> None:
    china_id = _valid_china_id()
    text = f"手机 13800138000，邮箱 demo@example.com，身份证 {china_id}"

    detections = PiiAnalyzer().analyze(text)

    assert {item.entity_type for item in detections} == {
        CN_PHONE_NUMBER,
        EMAIL_ADDRESS,
        CN_ID_NUMBER,
    }
    assert {item.masked_value for item in detections} == {
        "138****8000",
        "de***@example.com",
        f"{china_id[:3]}************{china_id[-3:]}",
    }


def test_rejects_invalid_china_id_checksum() -> None:
    valid_id = _valid_china_id()
    invalid_last = "0" if valid_id[-1] != "0" else "1"

    detections = PiiAnalyzer().analyze(valid_id[:-1] + invalid_last)

    assert detections == []


def test_redact_does_not_leave_raw_values() -> None:
    text = "phone=13800138000&email=demo@example.com"

    redacted = PiiAnalyzer().redact(text)

    assert "13800138000" not in redacted
    assert "demo@example.com" not in redacted
    assert redacted == "phone=138****8000&email=de***@example.com"
