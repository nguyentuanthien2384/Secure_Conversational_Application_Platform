from __future__ import annotations

import base64
from datetime import timedelta

from src.app.db import utcnow
from src.app.dlp import DLPScanner, FindingType
from src.app.ids import detect_anomalies
from src.app.models import AuditEvent
from src.app.services import AIService


def test_dlp_inspects_percent_and_base64_encoded_secrets():
    scanner = DLPScanner()
    encoded = base64.b64encode(b"password:super-secret-value").decode("ascii")

    redacted, findings = scanner.redact(
        f"percent=password%3Asuper-secret-value base64={encoded}"
    )

    assert "super-secret-value" not in redacted
    assert encoded not in redacted
    assert any(item.finding_type is FindingType.SECRET for item in findings)


def test_provider_output_is_scanned_before_display_truncation(settings):
    service = AIService(settings)

    class FakeProvider:
        def generate(self, *_args, **_kwargs):
            encoded = base64.b64encode(b"password:provider-secret").decode("ascii")
            return "x" * 8_100 + "\n" + encoded

    service._client = FakeProvider()
    output, labels = service.generate(
        "Explain security",
        [],
        allow_external_ai=True,
        data_class="public",
    )

    assert len(output) <= 8_000
    assert "provider-secret" not in output
    assert "mật khẩu" in labels


def test_ids_detects_distributed_guessing_and_failure_then_success(client, app):
    now = utcnow()
    with app.state.database.session_factory() as db:
        for index, source in enumerate(("198.51.100.10", "198.51.100.11", "198.51.100.12")):
            db.add(AuditEvent(
                actor_id="target-user",
                event_type="auth.login",
                outcome="failure",
                ip_address=source,
                created_at=now - timedelta(minutes=3, seconds=index),
                details_json="{}",
            ))
        db.add(AuditEvent(
            actor_id="target-user",
            event_type="auth.login",
            outcome="success",
            ip_address="198.51.100.12",
            created_at=now - timedelta(minutes=2),
            details_json="{}",
        ))
        db.commit()

        anomalies = detect_anomalies(
            db,
            window_minutes=60,
            brute_force_threshold=3,
            distributed_source_threshold=3,
        )

    by_code = {item.code: item for item in anomalies}
    assert by_code["IDS-DISTRIBUTED-BRUTEFORCE"].source_count == 3
    assert by_code["IDS-AUTH-SUCCESS-AFTER-FAILURES"].evidence_event_id is not None
