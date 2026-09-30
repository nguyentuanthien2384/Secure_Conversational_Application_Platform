from __future__ import annotations

import copy
import json
import os
import socket
import struct
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

import pytest

from scripts.practice_lab import main
from src.app import practice_runner as practice


@pytest.fixture(scope="module")
def practice_run(tmp_path_factory):
    output = tmp_path_factory.mktemp("practice-evidence")
    summary = practice.run_practice(["reconnaissance"], output)
    validation = json.loads((output / "security-validation.json").read_text(encoding="utf-8"))
    return output, summary, validation


def test_stage_selection_is_ordered_deduplicated_and_scoped():
    stages = practice.select_stages(["objectives", "reconnaissance", "objectives"])
    assert [stage["id"] for stage in stages] == ["reconnaissance", "objectives"]
    assert [stage["id"] for stage in practice.select_stages()] == list(practice.STAGE_IDS)
    assert [stage["id"] for stage in practice.select_stages(["all"])] == list(practice.STAGE_IDS)
    selected = [identifier for stage in practice.select_stages() for identifier in stage["scenario_ids"]]
    assert len(selected) == len(set(selected)) == 11
    assert set(selected) == {scenario.identifier for scenario in practice.SCENARIOS}
    lessons = practice.catalog()["lessons"]
    assert len(lessons) == len({lesson["id"] for lesson in lessons}) == 11
    for lesson in lessons:
        assert {"id", "title", "category", "stage", "objective", "steps", "expected_evidence", "questions", "completion", "scope"} <= lesson.keys()
        assert lesson["stage"] in practice.STAGE_IDS
        assert all(isinstance(lesson[field], str) and lesson[field] for field in ("id", "title", "category", "objective", "scope"))
        assert all(isinstance(lesson[field], list) and lesson[field] and all(isinstance(item, str) and item for item in lesson[field]) for field in ("steps", "expected_evidence", "questions", "completion"))
    modified = practice.catalog()
    modified["stages"][0]["scenario_ids"].clear()
    assert practice.catalog()["stages"][0]["scenario_ids"]
    for invalid in ([], ["unknown"], ["all", "scanning"], ["all", "all"]):
        with pytest.raises(ValueError):
            practice.select_stages(invalid)


def test_actual_subset_has_checks_correlated_sealed_evidence_and_artifacts(practice_run):
    output, summary, validation = practice_run
    assert summary["status"] == "pass"
    assert summary["total_scenarios"] == summary["passed_scenarios"] == 2
    assert summary["temporary_database_cleaned"] is True
    assert {case["id"] for case in validation["scenarios"]} == {"benign", "missing-auth"}
    stage = summary["stages"][0]
    assert stage["id"] == "reconnaissance" and stage["status"] == "pass"
    assert stage["total_checks"] == stage["passed_checks"] > 0
    assert any(request["sealed_evidence_ids"] for request in stage["requests"])
    for case in validation["scenarios"]:
        assert case["checks"] and all(check["passed"] for check in case["checks"])
        for request in case["requests"]:
            assert request["request_id"].startswith("sv-")
            for evidence in request["audit_evidence"]:
                assert evidence["request_id"] == request["request_id"] and evidence["sealed"]
    assert all((output / name).is_file() for name in summary["artifacts"].values())
    html = (output / "practice-report.html").read_text(encoding="utf-8")
    assert summary["run_id"] in html and "Request correlation ID" in html
    assert "không phải toàn bộ chuỗi tấn công mạng" in html
    assert "không có TLS" in html and "không thu thập mạng thật" in html
    assert '<html lang="vi">' in html


def test_export_is_allowlisted_and_html_escapes_dynamic_check_names(tmp_path, monkeypatch, practice_run):
    _, _, source = practice_run
    report = copy.deepcopy(source)
    private = "PRIVATE-SENTINEL-DO-NOT-EXPORT"
    report.update({"access_token": private, "password": private, "raw_body": private})
    for case in report["scenarios"]:
        case["details_json"] = private
        case["observations"] = [{"source": "untrusted", "body": private}]
        case["observations"] += [
            {"source": "in_process_security_telemetry", "event_type": "browser.origin.denied", "request_id": "safe-correlation-id", "outcome": "denied", "body": private, "token": private, "scope": private},
            {"source": "local_recording_provider", "provider_calls": 2, "external_network_calls": 0, "prompt": private},
            {"source": "temporary_session_timestamp_fixture", "details_json": private},
            {"source": "synthetic_audit_fixture", "audit_id": 7, "event_type": "auth.mfa.verify", "outcome": "success", "sealed": True, "actor_id": private},
            {"source": "anomaly_api_over_synthetic_fixtures", "code": "IDS-AUTH-SUCCESS-AFTER-FAILURES", "count": 5, "source_count": 5, "evidence_event_id": 7, "mitre_technique": "T1110", "ip_address": private},
        ]
        case["checks"][0]["name"] = '<script>alert("check")</script>'
        for request in case["requests"]:
            request.update({"headers": {"Authorization": private}, "body": private, "path": request["path"] + "?secret=" + private})
            for evidence in request["audit_evidence"]:
                evidence["details_json"] = private
    monkeypatch.setattr(practice, "run_validation", lambda _: report)
    assert main(["--stage", "reconnaissance", "--output-dir", str(tmp_path)]) == 0
    files = ["practice-report.html", "practice-summary.json", "security-validation.json", "security-validation.junit.xml"]
    for name in files:
        assert private not in (tmp_path / name).read_text(encoding="utf-8")
    html = (tmp_path / "practice-report.html").read_text(encoding="utf-8")
    assert '<script>alert("check")</script>' not in html
    assert "&lt;script&gt;alert(&quot;check&quot;)&lt;/script&gt;" in html
    assert "in_process_security_telemetry" in html and "safe-correlation-id" in html
    saved = json.loads((tmp_path / "security-validation.json").read_text(encoding="utf-8"))
    observations = saved["scenarios"][0]["observations"]
    assert {item["source"] for item in observations} == set(practice.OBSERVATION_SCOPES)
    provider = next(item for item in observations if item["source"] == "local_recording_provider")
    assert provider["provider_calls"] == 2 and provider["external_network_calls"] == 0
    assert next(item for item in observations if item["source"] == "synthetic_audit_fixture")["sealed"] is True


def test_actual_browser_denials_retain_ephemeral_telemetry_correlation(tmp_path):
    summary = practice.run_practice(["scanning"], tmp_path)
    assert summary["status"] == "pass"
    report = json.loads((tmp_path / "security-validation.json").read_text(encoding="utf-8"))
    browser = next(case for case in report["scenarios"] if case["id"] == "browser-origin")
    denials = {request["request_id"] for request in browser["requests"] if request["expected_status"] == 403}
    assert {item["request_id"] for item in browser["observations"]} == denials
    assert all(item["source"] == "in_process_security_telemetry" and item["event_type"] == "browser.origin.denied" for item in browser["observations"])
    html = (tmp_path / "practice-report.html").read_text(encoding="utf-8")
    assert "in_process_security_telemetry" in html
    assert all(request_id in html for request_id in denials)
    assert len([item for item in summary["stages"][0]["observations"] if item["scenario_id"] == "browser-origin"]) == 2


def test_failure_propagates_into_stage_json_html_junit_and_exit_code(tmp_path, monkeypatch, practice_run):
    _, _, source = practice_run
    report = copy.deepcopy(source)
    report["status"] = "fail"
    report["scenarios"][0]["status"] = "fail"
    report["scenarios"][0]["checks"][0]["passed"] = False
    monkeypatch.setattr(practice, "run_validation", lambda _: report)
    assert main(["--stage", "reconnaissance", "--output-dir", str(tmp_path)]) == 1
    summary = json.loads((tmp_path / "practice-summary.json").read_text(encoding="utf-8"))
    validation = json.loads((tmp_path / "security-validation.json").read_text(encoding="utf-8"))
    assert summary["status"] == summary["stages"][0]["status"] == "fail"
    assert summary["failed_scenarios"] == validation["failed_scenarios"] == 1
    suite = ElementTree.parse(tmp_path / "security-validation.junit.xml").getroot()
    assert suite.attrib["failures"] == "1" and len(suite.findall("testcase/failure")) == 1
    assert "CHƯA ĐẠT" in (tmp_path / "practice-report.html").read_text(encoding="utf-8")


def test_missing_scenario_cannot_be_reported_as_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(practice, "run_validation", lambda _: {"status": "pass", "scenarios": []})
    summary = practice.run_practice(["reconnaissance"], tmp_path)
    assert summary["status"] == "fail" and summary["failed_scenarios"] == 2


def _packet_records(content):
    magic, major, minor, timezone_offset, accuracy, snaplen, link = struct.unpack_from("<IHHIIII", content)
    assert (magic, major, minor, timezone_offset, accuracy, snaplen, link) == (0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    frames = []
    offset = 24
    while offset < len(content):
        seconds, microseconds, captured, original = struct.unpack_from("<IIII", content, offset)
        assert seconds == 1_700_000_000 and 0 <= microseconds < 1_000_000
        assert captured == original and 60 <= captured <= snaplen
        frame = content[offset + 16:offset + 16 + captured]
        assert len(frame) == captured
        frames.append(frame)
        offset += 16 + captured
    assert offset == len(content)
    return frames


def _valid_internet_checksum(data):
    words = [int.from_bytes(data[index:index + 2].ljust(2, b"\0"), "big") for index in range(0, len(data), 2)]
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def test_pcap_lengths_checksums_dns_alignment_and_tcp_handshake(tmp_path):
    pcap_path, guide_path = practice.write_packet_fixture(tmp_path)
    content = pcap_path.read_bytes()
    assert len(content) < 2500
    frames = _packet_records(content)
    assert len(frames) == 8
    segments = []
    endpoints = []
    for frame in frames:
        assert frame[12:14] == b"\x08\x00"
        ip = frame[14:]
        assert ip[0] == 0x45 and _valid_internet_checksum(ip[:20])
        ip_length = struct.unpack_from("!H", ip, 2)[0]
        assert 20 <= ip_length <= len(ip)
        assert not any(ip[ip_length:])  # Minimum Ethernet frame padding.
        source, destination = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        segment = ip[20:ip_length]
        pseudo = ip[12:20] + struct.pack("!BBH", 0, ip[9], len(segment))
        assert _valid_internet_checksum(pseudo + segment)
        if ip[9] == 17:
            assert struct.unpack_from("!H", segment, 4)[0] == len(segment)
            assert struct.unpack_from("!H", segment, 6)[0] != 0
        else:
            assert ip[9] == 6 and segment[12] >> 4 == 5
        segments.append(segment)
        endpoints.append((source, destination))
    query, reply = segments[0][8:], segments[1][8:]
    assert struct.unpack_from("!HHHHHH", query) == (0x5CA9, 0x0100, 1, 0, 0, 0)
    assert struct.unpack_from("!HHHHHH", reply) == (0x5CA9, 0x8180, 1, 1, 0, 0)
    question = b"\x08training\x07invalid\0\0\x01\0\x01"
    assert query[12:] == question and reply[12:12 + len(question)] == question
    answer = reply[12 + len(question):]
    assert answer[:2] == b"\xc0\x0c" and struct.unpack_from("!HHIH", answer, 2) == (1, 1, 60, 4)
    resolved = socket.inet_ntoa(answer[-4:])
    assert resolved == endpoints[2][1] == "203.0.113.20"
    tcp = segments[2:]
    assert [segment[13] for segment in tcp[:3]] == [0x02, 0x12, 0x10]
    assert [struct.unpack_from("!II", segment, 4) for segment in tcp[:3]] == [(1000, 0), (5000, 1001), (1001, 5001)]
    assert [struct.unpack_from("!HH", segment) for segment in tcp[:3]] == [(49000, 80), (80, 49000), (49000, 80)]
    request, response = tcp[3][20:], tcp[4][20:]
    assert request.startswith(b"GET /training HTTP/1.1\r\nHost: training.invalid\r\n")
    headers, body = response.split(b"\r\n\r\n", 1)
    assert headers.startswith(b"HTTP/1.1 200 OK")
    assert b"Content-Length: 17" in headers and len(body) == 17
    assert struct.unpack_from("!II", tcp[4], 4) == (5001, 1001 + len(request))
    assert struct.unpack_from("!II", tcp[5], 4) == (1001 + len(request), 5001 + len(response))
    guide = json.loads(guide_path.read_text(encoding="utf-8"))
    assert guide["synthetic"] and not guide["real_network_capture"] and not guide["contains_tls"]
    assert guide["outbound_packets_sent"] == 0
    assert [packet["number"] for packet in guide["packets"]] == list(range(1, 9))
    assert [item["packet_numbers"] for item in guide["questions"]] == [[1, 2], [3, 4, 5], [6, 7], []]
    assert guide["packets"][5]["payload_bytes"] == len(request)
    assert guide["packets"][6]["payload_bytes"] == len(response)


def test_fresh_cli_ignores_env_and_production_database(tmp_path):
    sentinel = tmp_path / "production.db"
    original = b"Production sentinel must not be opened"
    sentinel.write_bytes(original)
    (tmp_path / ".env").write_text(f"DATABASE_URL=sqlite:///{sentinel.as_posix()}\nAPP_ENV=production\n", encoding="utf-8")
    environment = os.environ.copy()
    environment.update({
        "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
        "DATABASE_URL": f"sqlite:///{sentinel.as_posix()}",
        "APP_SECRET_KEY_FILE": str(tmp_path / "nonexistent-secret-file"),
        "GOOGLE_GENAI_API_KEY_FILE": str(tmp_path / "nonexistent-key-file"),
        "GRADIO_ANALYTICS_ENABLED": "False",
    })
    completed = subprocess.run(
        [sys.executable, "-m", "scripts.practice_lab", "--stage", "reconnaissance", "--output-dir", str(tmp_path / "reports")],
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=90, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert sentinel.read_bytes() == original
    assert not (tmp_path / "secure_chat.db").exists()
    assert json.loads((tmp_path / "reports/practice-summary.json").read_text(encoding="utf-8"))["status"] == "pass"
