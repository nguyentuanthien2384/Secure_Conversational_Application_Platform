"""Offline practice artifacts for a dedicated CLI process.

Application checks use the existing temporary-database validator. The packet
fixture is generated from fixed bytes; no interfaces or external hosts are used.
Do not call this runner from the live application: validation temporarily patches
process-wide settings and HTTP transports while constructing isolated apps.
"""

from __future__ import annotations

import html
import ipaddress
import json
import re
import socket
import struct
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from src.app.practice import catalog
from src.app.security_validation import SCENARIOS, run_validation, write_reports

STAGE_IDS = ("reconnaissance", "scanning", "initial_access", "persistence", "objectives")
LIMITATION = (
    "Kết quả chỉ chứng minh các kiểm soát ứng dụng trong phòng lab cục bộ với SQLite tạm. "
    "Đây không phải toàn bộ chuỗi tấn công mạng, thử nghiệm khai thác thật, "
    "bằng chứng an toàn môi trường triển khai hoặc chứng nhận bảo mật production."
)
PACKET_LIMITATION = (
    "PCAP tổng hợp hoàn toàn từ dữ liệu cố định, không thu thập mạng thật và không gửi gói tin. "
    "Dùng địa chỉ TEST-NET và tên miền training.invalid. HTTP là văn bản rõ; "
    "không có TLS, giải mã TLS hoặc lưu lượng tấn công trong tệp này."
)
OBSERVATION_SCOPES = {
    "temporary_session_timestamp_fixture": "Đồng hồ phiên được mô phỏng bằng timestamp trong SQLite tạm; không chờ thời gian thật.",
    "local_recording_provider": "Biên nhà cung cấp AI được thay bằng stub cục bộ; DLP và API thực vẫn hoạt động, không gọi AI ngoài.",
    "synthetic_audit_fixture": "Dòng audit tổng hợp được niêm phong trong SQLite tạm; không phải lưu lượng từ nhiều máy thật.",
    "anomaly_api_over_synthetic_fixtures": "API tương quan thực đọc các dòng audit tổng hợp; không chứng minh điều tra sự kiện mạng thật.",
    "in_process_security_telemetry": "Telemetry bảo mật trong tiến trình được đối chiếu theo request ID; không phải audit bền vững hay SIEM ngoài.",
}


def select_stages(stage_ids: Sequence[str] | None = None) -> list[dict[str, Any]]:
    """Return requested stages in catalog order, rejecting ambiguous selection."""
    requested = list(stage_ids) if stage_ids is not None else ["all"]
    if not requested or any(item not in (*STAGE_IDS, "all") for item in requested):
        raise ValueError("Chọn ít nhất một giai đoạn hợp lệ")
    if "all" in requested and len(requested) > 1:
        raise ValueError("Không kết hợp all với một giai đoạn khác")
    selected = set(STAGE_IDS if requested == ["all"] else requested)
    stages = catalog()["stages"]
    by_id = {stage["id"]: stage for stage in stages}
    if selected - by_id.keys():
        raise ValueError("Danh mục thiếu giai đoạn đã chọn")
    known = {scenario.identifier for scenario in SCENARIOS}
    result = [stage for stage in stages if stage["id"] in selected]
    if any(not stage["scenario_ids"] or set(stage["scenario_ids"]) - known for stage in result):
        raise ValueError("Danh mục chứa kịch bản kiểm chứng không hợp lệ")
    return result


def _text(value: Any, limit: int = 240) -> str:
    return str(value or "")[:limit]


def _evidence(item: dict[str, Any]) -> dict[str, Any]:
    audit_id = item.get("audit_id")
    return {
        "audit_id": audit_id if isinstance(audit_id, int) and not isinstance(audit_id, bool) else None,
        "request_id": _text(item.get("request_id"), 160),
        "event_type": _text(item.get("event_type"), 80),
        "outcome": _text(item.get("outcome"), 40),
        "rule_id": _text(item.get("rule_id"), 80) or None,
        "sealed": item.get("sealed") is True,
    }


def _observations(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Retain typed proof metadata, excluding free-form audit or provider data."""
    observations = []
    for item in items[:100]:
        source = item.get("source")
        if not isinstance(source, str) or source not in OBSERVATION_SCOPES:
            continue
        observation = {"source": source, "scope": OBSERVATION_SCOPES[source]}
        for key in ("request_id", "event_type", "outcome", "code", "mitre_technique"):
            if key in item:
                observation[key] = _text(item[key], 160)
        for key in ("audit_id", "evidence_event_id", "count", "source_count", "provider_calls", "external_network_calls"):
            value = item.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1_000_000:
                observation[key] = value
        if "sealed" in item:
            observation["sealed"] = item["sealed"] is True
        observations.append(observation)
    return observations


def _safe_report(report: dict[str, Any], scenario_ids: list[str]) -> dict[str, Any]:
    """Keep the validator's bounded evidence fields; never copy arbitrary objects."""
    cases = {item["id"]: item for item in report.get("scenarios", [])[:len(SCENARIOS)]}
    known = {scenario.identifier: scenario for scenario in SCENARIOS}
    scenarios = []
    for identifier in scenario_ids:
        case = cases.get(identifier, {})
        checks = [
            {"name": _text(item.get("name")), "passed": item.get("passed") is True}
            for item in case.get("checks", [])[:300]
        ]
        if not case:
            checks = [{"name": "Kịch bản đã chọn không có kết quả kiểm chứng", "passed": False}]
        requests = [
            {
                "request_id": _text(item.get("request_id"), 160),
                "phase": _text(item.get("phase"), 24),
                "method": _text(item.get("method"), 12),
                "path": _text(item.get("path"), 160).partition("?")[0],
                "expected_status": _status_code(item.get("expected_status")),
                "observed_status": _status_code(item.get("observed_status")),
                "expected_event": _text(item.get("expected_event"), 80) or None,
                "latency_ms": _duration(item.get("latency_ms")),
                "audit_observation_latency_ms": _duration(item.get("audit_observation_latency_ms")),
                "audit_evidence": [_evidence(row) for row in item.get("audit_evidence", [])[:50]],
            }
            for item in case.get("requests", [])[:100]
        ]
        error_type = _text(case.get("error_type"), 80)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", error_type):
            error_type = "ValidationError" if error_type else None
        passed = case.get("status") == "pass" and bool(checks) and all(item["passed"] for item in checks) and not error_type
        scenarios.append({
            "id": identifier, "name": known[identifier].name,
            "kind": known[identifier].kind, "mitre_technique": known[identifier].technique,
            "scope": known[identifier].scope, "status": "pass" if passed else "fail",
            "duration_ms": _duration(case.get("duration_ms")) or 0,
            "checks": checks, "requests": requests,
            "observations": _observations(case.get("observations", [])), "error_type": error_type,
        })
    passed_count = sum(case["status"] == "pass" for case in scenarios)
    failed_count = len(scenarios) - passed_count
    return {
        "schema_version": 1, "run_id": _text(report.get("run_id"), 64),
        "completed_at": _text(report.get("completed_at"), 64),
        "validation_type": "isolated_application_security_validation",
        "scope": LIMITATION,
        "not_covered": ["Production", "Real network capture", "Host compromise", "Full attack lifecycle", "TLS analysis"],
        "timing_definition": "Độ trễ xử lý cục bộ; không phải độ trễ SIEM bên ngoài.",
        "temporary_database_cleaned": report.get("temporary_database_cleaned") is True,
        "total_scenarios": len(scenarios), "passed_scenarios": passed_count,
        "failed_scenarios": failed_count,
        "status": "pass" if not failed_count and report.get("status") == "pass" else "fail",
        "duration_ms": _duration(report.get("duration_ms")) or 0,
        "scenarios": scenarios,
    }


def _duration(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 86_400_000:
        return round(value, 3)
    return None


def _status_code(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599 else None


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip_packet(source: str, destination: str, protocol: int, payload: bytes, packet_id: int) -> bytes:
    src = ipaddress.IPv4Address(source).packed
    dst = ipaddress.IPv4Address(destination).packed
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), packet_id, 0x4000, 64, protocol, 0, src, dst)
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return header + payload


def _udp(source: str, destination: str, source_port: int, destination_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    segment = struct.pack("!HHHH", source_port, destination_port, length, 0) + payload
    pseudo = socket.inet_aton(source) + socket.inet_aton(destination) + struct.pack("!BBH", 0, 17, length)
    checksum = _checksum(pseudo + segment) or 0xFFFF
    return segment[:6] + struct.pack("!H", checksum) + segment[8:]


def _tcp(source: str, destination: str, source_port: int, destination_port: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    segment = struct.pack("!HHIIBBHHH", source_port, destination_port, seq, ack, 0x50, flags, 8192, 0, 0) + payload
    pseudo = socket.inet_aton(source) + socket.inet_aton(destination) + struct.pack("!BBH", 0, 6, len(segment))
    return segment[:16] + struct.pack("!H", _checksum(pseudo + segment)) + segment[18:]


def write_packet_fixture(output_dir: Path) -> tuple[Path, Path]:
    """Generate one small Ethernet/IPv4/DNS/TCP/HTTP PCAP without network I/O."""
    output_dir.mkdir(parents=True, exist_ok=True)
    client, dns, server = "192.0.2.10", "198.51.100.53", "203.0.113.20"
    macs = {client: bytes.fromhex("020000000010"), dns: bytes.fromhex("020000000053"), server: bytes.fromhex("020000000020")}
    qname = b"\x08training\x07invalid\0"
    question = qname + struct.pack("!HH", 1, 1)
    dns_query = struct.pack("!HHHHHH", 0x5CA9, 0x0100, 1, 0, 0, 0) + question
    dns_reply = struct.pack("!HHHHHH", 0x5CA9, 0x8180, 1, 1, 0, 0) + question
    dns_reply += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(server)
    request = b"GET /training HTTP/1.1\r\nHost: training.invalid\r\nUser-Agent: SCAP-Offline-Lab\r\n\r\n"
    body = b"SCAP offline lab\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
    packets = [
        (client, dns, 17, _udp(client, dns, 53000, 53, dns_query)),
        (dns, client, 17, _udp(dns, client, 53, 53000, dns_reply)),
        (client, server, 6, _tcp(client, server, 49000, 80, 1000, 0, 0x02)),
        (server, client, 6, _tcp(server, client, 80, 49000, 5000, 1001, 0x12)),
        (client, server, 6, _tcp(client, server, 49000, 80, 1001, 5001, 0x10)),
        (client, server, 6, _tcp(client, server, 49000, 80, 1001, 5001, 0x18, request)),
        (server, client, 6, _tcp(server, client, 80, 49000, 5001, 1001 + len(request), 0x18, response)),
        (client, server, 6, _tcp(client, server, 49000, 80, 1001 + len(request), 5001 + len(response), 0x10)),
    ]
    content = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for number, (source, destination, protocol, payload) in enumerate(packets, 1):
        frame = macs[destination] + macs[source] + b"\x08\x00" + _ip_packet(source, destination, protocol, payload, number)
        frame = frame.ljust(60, b"\0")  # Ethernet minimum frame size without FCS.
        content.extend(struct.pack("<IIII", 1_700_000_000, (number - 1) * 100_000, len(frame), len(frame)))
        content.extend(frame)
    pcap_path = output_dir / "network-training.pcap"
    pcap_path.write_bytes(content)
    guide = {
        "schema_version": 1, "synthetic": True, "real_network_capture": False,
        "outbound_packets_sent": 0, "contains_tls": False,
        "scope": PACKET_LIMITATION, "packet_count": len(packets),
        "addresses": {"client": client, "dns": dns, "http_server": server},
        "domain": "training.invalid", "link_type": "Ethernet", "timestamp_source": "fixed synthetic timestamps",
        "packets": [
            {"number": 1, "protocol": "DNS/UDP", "purpose": "Truy vấn A training.invalid", "source": client, "destination": dns, "source_port": 53000, "destination_port": 53},
            {"number": 2, "protocol": "DNS/UDP", "purpose": "Trả lời A 203.0.113.20, cùng transaction ID 0x5ca9", "source": dns, "destination": client, "source_port": 53, "destination_port": 53000},
            {"number": 3, "protocol": "TCP", "purpose": "SYN, sequence=1000", "source": client, "destination": server, "flags": "SYN"},
            {"number": 4, "protocol": "TCP", "purpose": "SYN/ACK, sequence=5000, acknowledgment=1001", "source": server, "destination": client, "flags": "SYN,ACK"},
            {"number": 5, "protocol": "TCP", "purpose": "ACK, sequence=1001, acknowledgment=5001; kết thúc bắt tay", "source": client, "destination": server, "flags": "ACK"},
            {"number": 6, "protocol": "HTTP/TCP", "purpose": "GET /training, Host: training.invalid", "source": client, "destination": server, "flags": "PSH,ACK", "payload_bytes": len(request)},
            {"number": 7, "protocol": "HTTP/TCP", "purpose": "HTTP/1.1 200 OK, Content-Length: 17", "source": server, "destination": client, "flags": "PSH,ACK", "payload_bytes": len(response)},
            {"number": 8, "protocol": "TCP", "purpose": "ACK xác nhận toàn bộ phản hồi HTTP", "source": client, "destination": server, "flags": "ACK"},
        ],
        "questions": [
            {"question": "Gói nào truy vấn DNS và gói nào trả lời?", "filter": "dns", "packet_numbers": [1, 2], "answer": "Gói 1 truy vấn A training.invalid; gói 2 trả lời 203.0.113.20; transaction ID đều là 0x5ca9."},
            {"question": "Ba bước bắt tay TCP nằm ở đâu?", "filter": "tcp.stream eq 0", "packet_numbers": [3, 4, 5], "answer": "Gói 3 SYN; gói 4 SYN/ACK; gói 5 ACK. Cổng máy khách 49000, máy chủ 80; số ACK là SEQ của phía đối diện cộng 1."},
            {"question": "Yêu cầu và phản hồi HTTP là gói nào?", "filter": "http", "packet_numbers": [6, 7], "answer": "Gói 6 GET /training với Host training.invalid; gói 7 trả mã 200 và 17 byte nội dung lành tính."},
            {"question": "Có thể kết luận gì về HTTPS/TLS hoặc mạng thật?", "filter": "tls", "packet_numbers": [], "answer": "Không có gói TLS. Tệp được tổng hợp, không chứng minh lưu lượng mạng thật, mã hóa HTTPS hay phát hiện tấn công."},
        ],
    }
    guide_path = output_dir / "network-training.json"
    guide_path.write_text(json.dumps(guide, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return pcap_path, guide_path


def _render_html(summary: dict[str, Any], validation: dict[str, Any], guide: dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return html.escape(_text(value, 1000), quote=True)
    by_id = {case["id"]: case for case in validation["scenarios"]}
    sections = []
    for stage in summary["stages"]:
        details = []
        for scenario_id in stage["scenario_ids"]:
            case = by_id[scenario_id]
            checks = "".join(f'<li class="{item["passed"] and "pass" or "fail"}">{"ĐẠT" if item["passed"] else "CHƯA ĐẠT"}: {esc(item["name"])}</li>' for item in case["checks"])
            requests = []
            for request in case["requests"]:
                evidence = "; ".join(
                    f'#{row["audit_id"]} {esc(row["event_type"])} ({"đã niêm phong" if row["sealed"] else "chưa niêm phong"})'
                    for row in request["audit_evidence"]
                ) or "Không có audit bền vững; xem bằng chứng telemetry/fixture bên dưới nếu có"
                requests.append(f'<tr><td><code>{esc(request["request_id"])}</code></td><td>{esc(request["method"])} {esc(request["path"])}</td><td>{esc(request["expected_status"])} / {esc(request["observed_status"])}</td><td>{evidence}</td></tr>')
            observations = "".join(
                f'<li><strong>Nguồn: <code>{esc(item["source"])}</code></strong>'
                + "".join(f' · {esc(key)}: <code>{esc(value)}</code>' for key, value in item.items() if key not in {"source", "scope"})
                + f'<p>{esc(item["scope"])}</p></li>'
                for item in case["observations"]
            )
            observation_section = f'<h3>Bằng chứng quan sát</h3><ul>{observations}</ul>' if observations else ""
            details.append(
                f'<details><summary class="{case["status"]}">{"ĐẠT" if case["status"] == "pass" else "CHƯA ĐẠT"}: {esc(scenario_id)}</summary>'
                f'<p>{esc(case["scope"])}</p><ul>{checks}</ul><div class="scroll"><table><thead><tr><th>Request correlation ID</th><th>Yêu cầu</th><th>Mong đợi / thực tế</th><th>ID bằng chứng audit</th></tr></thead><tbody>{"".join(requests)}</tbody></table></div>{observation_section}</details>'
            )
        sections.append(f'<section><h2 class="{stage["status"]}">{esc(stage["title"])} — {"ĐẠT" if stage["status"] == "pass" else "CHƯA ĐẠT"}</h2><p>{esc(stage["scope"])}</p>{"".join(details)}</section>')
    packets = "".join(f'<tr><td>{item["number"]}</td><td>{esc(item["protocol"])}</td><td>{esc(item["purpose"])}</td></tr>' for item in guide["packets"])
    questions = "".join(f'<details><summary>{esc(item["question"])}</summary><p>Bộ lọc Wireshark: <code>{esc(item["filter"])}</code></p><p>{esc(item["answer"])}</p></details>' for item in guide["questions"])
    return f'''<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'"><title>SCAP — Báo cáo thực hành</title><style>
body{{font:16px/1.6 system-ui,sans-serif;margin:auto;padding:24px;max-width:1150px;background:#f5f7fb;color:#183046}}h1,h2{{line-height:1.3}}section,aside,header{{background:white;padding:24px;margin:20px 0;border-radius:12px}}aside{{border-left:5px solid #ca8a04}}.pass{{color:#117344}}.fail{{color:#b02f2f}}details{{margin:14px 0}}summary{{cursor:pointer;font-weight:650}}table{{width:100%;border-collapse:collapse;font-size:14px}}th,td{{border:1px solid #d8e1eb;padding:8px;text-align:left;vertical-align:top}}code{{overflow-wrap:anywhere}}.scroll{{overflow:auto}}a{{color:#1555a3}}
</style></head><body><header><h1>SCAP — Báo cáo thực hành 5 giai đoạn</h1><p class="{summary["status"]}"><strong>{"ĐẠT" if summary["status"] == "pass" else "CHƯA ĐẠT"}: {summary["passed_scenarios"]}/{summary["total_scenarios"]} kịch bản ứng dụng</strong></p><p>Run ID: <code>{esc(summary["run_id"])}</code> · Hoàn tất (UTC): {esc(summary["completed_at"])}</p></header><aside><strong>Phạm vi bằng chứng</strong><p>{esc(LIMITATION)}</p><p>Đối chiếu mã yêu cầu với ID audit đã niêm phong. Mã phản hồi đúng vẫn có thể CHƯA ĐẠT khi thiếu bằng chứng. Các ID audit chỉ có ý nghĩa trong SQLite tạm của từng kịch bản; CSDL được xóa sau kiểm chứng.</p><p>Phòng lab chạy trong tiến trình riêng; không nhập URL mục tiêu và không dùng dữ liệu thật.</p></aside>{"".join(sections)}<section><h2>Thực hành đọc gói tin DNS → TCP → HTTP</h2><p>{esc(PACKET_LIMITATION)}</p><p><a href="network-training.pcap" download>Mở PCAP bằng Wireshark</a> · <a href="network-training.json">Hướng dẫn JSON</a></p><div class="scroll"><table><thead><tr><th>Gói</th><th>Giao thức</th><th>Đáp án</th></tr></thead><tbody>{packets}</tbody></table></div>{questions}</section><section><h2>Tệp bằng chứng</h2><p><a href="security-validation.json">Kết quả kiểm chứng JSON</a> · <a href="security-validation.junit.xml">JUnit</a> · <a href="practice-summary.json">Tổng hợp thực hành JSON</a></p><p>Báo cáo không chứa token, mật khẩu, nội dung hội thoại hoặc trường chi tiết audit.</p></section></body></html>'''


def run_practice(stage_ids: Sequence[str] | None, output_dir: Path) -> dict[str, Any]:
    """Run selected application exercises, then write all reviewable artifacts."""
    stages = select_stages(stage_ids)
    selected = list(dict.fromkeys(identifier for stage in stages for identifier in stage["scenario_ids"]))
    validation = _safe_report(run_validation(selected), selected)
    json_path, junit_path = write_reports(validation, output_dir)
    pcap_path, guide_path = write_packet_fixture(output_dir)
    by_id = {case["id"]: case for case in validation["scenarios"]}
    stage_results = []
    for stage in stages:
        cases = [by_id[identifier] for identifier in stage["scenario_ids"]]
        stage_results.append({
            "id": stage["id"], "title": _text(stage["title"]), "scope": _text(stage["scope"], 1000),
            "scenario_ids": list(stage["scenario_ids"]),
            "status": "pass" if all(case["status"] == "pass" for case in cases) else "fail",
            "total_checks": sum(len(case["checks"]) for case in cases),
            "passed_checks": sum(check["passed"] for case in cases for check in case["checks"]),
            "requests": [
                {"scenario_id": case["id"], "request_id": request["request_id"],
                 "expected_status": request["expected_status"], "observed_status": request["observed_status"],
                 "sealed_evidence_ids": [item["audit_id"] for item in request["audit_evidence"] if item["sealed"] and item["audit_id"] is not None]}
                for case in cases for request in case["requests"]
            ],
            "observations": [{"scenario_id": case["id"], **item} for case in cases for item in case["observations"]],
        })
    summary = {
        "schema_version": 1, "run_id": validation["run_id"], "completed_at": validation["completed_at"],
        "practice_type": "isolated_application_checks_and_synthetic_packet_fixture",
        "scope": LIMITATION, "packet_scope": PACKET_LIMITATION,
        "status": validation["status"], "total_scenarios": validation["total_scenarios"],
        "passed_scenarios": validation["passed_scenarios"], "failed_scenarios": validation["failed_scenarios"],
        "temporary_database_cleaned": validation["temporary_database_cleaned"],
        "stages": stage_results,
        "artifacts": {"validation_json": json_path.name, "validation_junit": junit_path.name,
                      "summary": "practice-summary.json", "html": "practice-report.html",
                      "pcap": pcap_path.name, "packet_guide": guide_path.name},
    }
    (output_dir / "practice-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    guide = json.loads(guide_path.read_text(encoding="utf-8"))
    (output_dir / "practice-report.html").write_text(_render_html(summary, validation, guide), encoding="utf-8")
    return summary
