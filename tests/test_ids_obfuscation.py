from __future__ import annotations

from urllib.parse import quote

import pytest

from src.app.ids import MAX_SCAN_TEXT_CHARS, Detection, IntrusionState, scan_text


@pytest.mark.parametrize(
    "payload, expected_rule",
    [
        ("id=0 OR/**/1=1", "SQLI-002"),
        ("id=0 UNION/*" + "padding" * 20 + "*/SELECT password", "SQLI-001"),
        ("id=0 /*!50000UNION*/ /*!50000SELECT*/ password", "SQLI-001"),
        ("q=&#x3c;script&#x3e;alert(1)", "XSS-001"),
        ("q=%26%23x3c%3Bscript%26%23x3e%3Balert(1)", "XSS-001"),
        (r"q=\u003cscript\u003ealert(1)", "XSS-001"),
        (r"q=\x3cscript\x3ealert(1)", "XSS-001"),
        ("url=java&#x09;script:alert(1)", "XSS-001"),
        ("url=jav\nascr\ript:alert(1)", "XSS-001"),
        (quote(quote(quote("file=../../etc/passwd", safe=""), safe=""), safe=""), "TRAV-001"),
    ],
)
def test_obfuscated_probe_is_detected(payload: str, expected_rule: str):
    assert expected_rule in {rule_id for rule_id, *_ in scan_text(payload)}


@pytest.mark.parametrize(
    "text",
    [
        "/api/health?topic=coffee+tea",
        "q=Tiếng%20Việt%20và%20bảo%20mật",
        "q=Tom%20%26amp%3B%20Jerry",
        "q=10%25+discount",
        # Removing newlines for SQL would join two unrelated words into OR.
        "q=or\nange 1=1",
        "q=%zz&#broken;\\u00xz",
        "/*" * (MAX_SCAN_TEXT_CHARS // 2),
    ],
)
def test_normalization_does_not_flag_benign_or_malformed_text(text: str):
    assert scan_text(text) == []


def test_scanning_is_deterministic_and_emits_each_rule_once():
    payload = "q=<script>1' OR '1'='1 UNION SELECT a</script>&other=%3Cscript%3E"
    first = scan_text(payload)
    assert first == scan_text(payload)
    rule_ids = [hit[0] for hit in first]
    assert len(rule_ids) == len(set(rule_ids))
    assert {"SQLI-001", "SQLI-002", "XSS-001"} <= set(rule_ids)


def test_scan_size_limit_never_silently_skips_payload_tail():
    payload = "<script>"
    text = "x" * (MAX_SCAN_TEXT_CHARS - len(payload)) + payload
    assert "XSS-001" in {rule_id for rule_id, *_ in scan_text(text)}
    with pytest.raises(ValueError, match="request-target limit"):
        scan_text("x" + text)


def _detection(source_ip: str, severity: str = "high") -> Detection:
    return Detection(
        rule_id="SQLI-001",
        severity=severity,
        engine="signature",
        description="in-process test",
        source_ip=source_ip,
        path="/api/health",
        method="GET",
        evidence_sha256="test-digest",
    )


def test_served_block_expires_without_requiring_an_is_blocked_call(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("src.app.ids.time.monotonic", lambda: clock[0])
    state = IntrusionState(block_threshold=5, block_seconds=10)
    assert not state.record(_detection("192.0.2.1"))
    assert state.record(_detection("192.0.2.1"))
    clock[0] = 110.0
    assert not state.record(_detection("192.0.2.1"))
    assert state.is_blocked("192.0.2.1") == (False, 0)
    assert state.record(_detection("192.0.2.1"))


def test_manual_unblock_starts_a_fresh_score_window():
    state = IntrusionState(block_threshold=5)
    state.record(_detection("192.0.2.1"))
    assert state.record(_detection("192.0.2.1"))
    assert state.unblock("192.0.2.1")
    assert not state.record(_detection("192.0.2.1"))
    assert state.is_blocked("192.0.2.1") == (False, 0)


def test_idle_source_scores_and_blocks_are_reclaimed(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("src.app.ids.time.monotonic", lambda: clock[0])
    state = IntrusionState(block_threshold=5, block_seconds=10)
    state.record(_detection("192.0.2.1", "low"))
    state.record(_detection("192.0.2.2"))
    state.record(_detection("192.0.2.2"))
    clock[0] = 111.0
    # A different address triggers cleanup; the old addresses never return.
    assert state.is_blocked("192.0.2.3") == (False, 0)
    assert state._scores == {}
    assert state.blocked_sources() == []


def test_source_capacity_preserves_active_blocks_and_bounds_scores():
    state = IntrusionState(block_threshold=3, max_sources=2, history=4)
    assert state.record(_detection("192.0.2.1"))
    assert not state.record(_detection("192.0.2.2", "low"))
    assert state.record(_detection("192.0.2.3"))
    assert state.is_blocked("192.0.2.1")[0]
    assert state.is_blocked("192.0.2.3")[0]
    assert "192.0.2.2" not in state._scores
    assert not state.record(_detection("192.0.2.4"))
    assert len(state._scores) == 2
    assert len(state.blocked_sources()) == 2
    assert len(state.recent()) == 4
    assert state.recent()[0]["source_ip"] == "192.0.2.4"
    for _ in range(10):
        state.record(_detection("192.0.2.1"))
    assert len(state._scores["192.0.2.1"]) == state.block_threshold


@pytest.mark.parametrize(
    "kwargs",
    [{"block_threshold": 0}, {"block_seconds": 0}, {"history": 0}, {"max_sources": 0}],
)
def test_intrusion_state_requires_positive_resource_limits(kwargs):
    with pytest.raises(ValueError, match="must be positive"):
        IntrusionState(**kwargs)
