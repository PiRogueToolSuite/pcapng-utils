import json
from pathlib import Path

from pcapng_utils.pii.pipeline import scan_pcapng


def _fake_har() -> dict:
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://example.test/?phone=13800138000",
                    },
                    "response": {"content": {"mimeType": "text/plain", "text": "ok"}},
                }
            ]
        }
    }


def test_pipeline_uses_and_removes_temporary_har(tmp_path, monkeypatch) -> None:
    input_path = tmp_path / "capture.pcapng"
    input_path.write_bytes(b"synthetic")
    converted_paths: list[Path] = []

    def fake_convert(input_file, output_file, **kwargs) -> None:
        assert input_file == input_path
        assert kwargs["tshark"].tshark_cmd == "custom-tshark"
        converted_paths.append(output_file)
        output_file.write_text(json.dumps(_fake_har()), encoding="utf-8")

    monkeypatch.setattr("pcapng_utils.pii.pipeline.pcapng_to_har", fake_convert)

    report = scan_pcapng(input_path, tshark_command="custom-tshark")

    assert report["source"] == "capture.pcapng"
    assert report["source_format"] == "pcapng"
    assert report["summary"]["finding_count"] == 1
    assert report["summary"]["unique_finding_count"] == 1
    assert len(converted_paths) == 1
    assert not converted_paths[0].exists()


def test_pipeline_can_retain_intermediate_har(tmp_path, monkeypatch) -> None:
    input_path = tmp_path / "capture.pcapng"
    input_path.write_bytes(b"synthetic")
    har_output = tmp_path / "retained.har"

    def fake_convert(input_file, output_file, **kwargs) -> None:
        output_file.write_text(json.dumps(_fake_har()), encoding="utf-8")

    monkeypatch.setattr("pcapng_utils.pii.pipeline.pcapng_to_har", fake_convert)

    scan_pcapng(input_path, har_output=har_output)

    assert har_output.is_file()
