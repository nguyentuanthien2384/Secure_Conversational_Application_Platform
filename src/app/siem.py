"""Structured security logging (Bài 1 §Accounting, Bài 7 §SIEM, Bài 8 §DevSecOps).

The audit trail already lives in the database, which is right for forensics but
wrong for *detection*: a SIEM cannot poll a table. This module mirrors every
security-relevant event to stdout as one JSON object per line, which is the
format Loki / Elastic / Splunk / Wazuh ingest without a custom parser.

Design rules:
- One line per event, never multi-line (a stack trace split across lines breaks
  log-shipping and enables log-injection).
- Field names follow Elastic Common Schema loosely so dashboards are portable.
- Absolutely no secrets: no passwords, tokens, plaintext messages or TOTP seeds.
  Callers pass lengths and identifiers, never content.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

SIEM_LOGGER_NAME = "security.siem"

_SEVERITY_BY_OUTCOME = {
    "success": "info",
    "failure": "warning",
    "denied": "warning",
    "blocked": "high",
}

# Events that always deserve attention even when they "succeed".
_HIGH_VALUE_EVENTS = {
    "auth.mfa.disabled",
    "auth.password_change",
    "admin.user.delete",
    "admin.user.role",
    "admin.user.status",
    "ids.block",
    "audit.chain.broken",
}


class JsonLineFormatter(logging.Formatter):
    """Render a LogRecord as a single-line JSON document."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "@timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "log.level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "security_event", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            # Collapse to a single field; never emit a multi-line traceback here.
            payload["error.type"] = getattr(record.exc_info[0], "__name__", "Exception")
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_siem_logging(enabled: bool = True, level: int = logging.INFO) -> logging.Logger:
    """Attach a single JSON-lines handler on stdout. Idempotent."""
    logger = logging.getLogger(SIEM_LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False
    logger.disabled = not enabled
    if not any(getattr(h, "_siem_handler", False) for h in logger.handlers):
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(JsonLineFormatter())
        handler._siem_handler = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    return logger


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("\r", " ").replace("\n", " ")[:512]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:512]


def emit_security_event(
    event_type: str,
    *,
    outcome: str = "success",
    actor_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    audit_id: int | None = None,
    entry_hash: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Write one SIEM line. Never raises — logging must not break a request."""
    logger = logging.getLogger(SIEM_LOGGER_NAME)
    if logger.disabled:
        return
    severity = _SEVERITY_BY_OUTCOME.get(outcome, "info")
    if event_type in _HIGH_VALUE_EVENTS and severity == "info":
        severity = "notice"
    document = {
        "event.dataset": "scap.audit",
        "event.action": event_type,
        "event.outcome": outcome,
        "event.severity": severity,
        "user.id": actor_id,
        "target.type": target_type,
        "target.id": target_id,
        "source.ip": source_ip,
        "user_agent.original": _scrub(user_agent) if user_agent else None,
        "http.request.id": request_id,
        "audit.id": audit_id,
        "audit.entry_hash": entry_hash,
    }
    for key, value in (details or {}).items():
        document[f"scap.{str(key)[:40]}"] = _scrub(value)
    document = {k: v for k, v in document.items() if v is not None}
    level = logging.WARNING if severity in {"warning", "high"} else logging.INFO
    try:
        logger.log(
            level,
            f"{event_type} {outcome}",
            extra={"security_event": document},
        )
    except Exception:  # pragma: no cover - logging must never break the request
        pass
