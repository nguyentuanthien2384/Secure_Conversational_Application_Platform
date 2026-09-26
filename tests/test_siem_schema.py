from __future__ import annotations

import json
import logging

import pytest

from src.app.siem import SIEM_LOGGER_NAME, JsonLineFormatter, emit_security_event


@pytest.mark.parametrize("outcome, expected", [
    ("success", "success"), ("failure", "failure"),
    ("denied", "failure"), ("blocked", "failure"), ("other", "unknown"),
])
def test_siem_uses_ecs_types_and_preserves_decision(monkeypatch, outcome, expected):
    logger = logging.getLogger(SIEM_LOGGER_NAME)
    monkeypatch.setattr(logger, "disabled", False)
    records = []
    monkeypatch.setattr(logger, "log", lambda level, msg, **kw: records.append(kw["extra"]["security_event"]))
    emit_security_event("ids.signature", outcome=outcome, request_id="trace-1", details={"mitre_technique": "T1190"})
    document = records[0]
    assert document["event.outcome"] == expected
    assert isinstance(document["event.severity"], int)
    assert document["scap.outcome"] == outcome
    assert document["http.request.id"] == "trace-1"
    assert document["threat.technique.id"] == ["T1190"]


def test_formatter_keeps_untrusted_newlines_in_one_json_line():
    record = logging.LogRecord(SIEM_LOGGER_NAME, logging.WARNING, "", 1, "test\nforged", (), None)
    record.security_event = {"event.action": "test", "scap.detail": "a\r\nb"}
    formatted = JsonLineFormatter().format(record)
    assert len(formatted.splitlines()) == 1
    assert json.loads(formatted)["event.action"] == "test"
