"""Encoded exfiltration, inspection budgets, and real AI-boundary regressions.

All credentials are synthetic; providers are local recording fakes.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import replace

import pytest
from sqlalchemy import func, select

from src.app import dlp
from src.app.dlp import CustomDictionary, DataClass, DLPAction, DLPScanner, FindingType
from src.app.models import AuditEvent, SecureMessage
from src.app.services import (
    AI_UNAVAILABLE_MESSAGE,
    MAX_PROVIDER_RESPONSE_CHARACTERS,
    AIProviderError,
    AIService,
    DLPPolicyViolation,
)
from tests.conftest import register_and_login


def _base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _percent(text: str) -> str:
    return "".join(f"%{byte:02X}" for byte in text.encode("utf-8"))


def _entities(text: str) -> str:
    return "".join(f"&#{ord(char)};" for char in text)


@pytest.mark.parametrize(
    "encode",
    [
        _base64,
        lambda text: base64.urlsafe_b64encode(text.encode()).decode().rstrip("="),
        _percent,
        _entities,
        lambda text: "".join(f"&#x{ord(char):x};" for char in text),
        lambda text: _base64(_percent(text)),
        lambda text: _entities(_base64(text)),
        lambda text: _base64(_entities(_percent(text))),
    ],
    ids=["base64", "base64url", "percent", "entities", "hex-entities", "nested", "mixed", "three-layers"],
)
def test_encoded_credentials_raise_policy_and_redact_source(encode):
    secret = "password:secret-đặc-biệt??????"
    encoded = encode(secret)
    scanner = DLPScanner()
    text = f"before ;{encoded}; after"

    decision = scanner.evaluate(text, data_class="public", confirmed=True)
    redacted, findings = scanner.redact(text)

    assert decision.action is DLPAction.BLOCK
    assert decision.output_text is None
    assert FindingType.SECRET in {item.finding_type for item in findings}
    assert encoded not in redacted
    assert "secret-đặc-biệt" not in redacted
    assert redacted.startswith("before ;") and redacted.endswith("; after")
    public_report = json.dumps(decision.safe_report(), ensure_ascii=False) + repr(decision)
    assert encoded not in public_report and "secret-đặc-biệt" not in public_report


def test_urlsafe_base64_accepts_url_alphabet_and_missing_padding():
    encoded = base64.urlsafe_b64encode(b"password:??????").decode().rstrip("=")
    assert "_" in encoded
    assert DLPScanner().evaluate(encoded).action is DLPAction.BLOCK


@pytest.mark.parametrize(
    "text",
    [
        "password%3Asynthetic-secret",
        "pa%73sword=synthetic-secret",
        "password&colon;synthetic-secret",
        "p&#97;ssword&#61;synthetic-secret",
        "password%253Asynthetic-secret",
        "p%26%2397%3Bssword%26colon%3Bsynthetic-secret",
    ],
)
def test_partial_and_nested_escape_keeps_surrounding_context(text):
    scanner = DLPScanner()
    assert scanner.evaluate(text).action is DLPAction.BLOCK
    redacted, findings = scanner.redact("prefix " + text + " suffix")
    assert "synthetic-secret" not in redacted
    assert redacted.startswith("prefix ") and redacted.endswith(" suffix")
    assert any(item.finding_type is FindingType.SECRET for item in findings)


@pytest.mark.parametrize("email", ["a@b.co", "person@example.com"])
def test_encoded_pii_is_redacted_under_existing_confidential_policy(email):
    encoded = _base64(email)
    decision = DLPScanner().evaluate(f"Contact ({encoded})", data_class="public")
    assert decision.action is DLPAction.REDACT
    assert decision.effective_data_class is DataClass.CONFIDENTIAL
    assert decision.output_text == "Contact ([REDACTED:EMAIL])"


@pytest.mark.parametrize("suffix", [".", "...", ". Next sentence", ",", ";", ":", "!", "?", ")", '"'])
def test_email_sentence_punctuation_preserved_and_encoded_email_is_redacted(suffix):
    text = "person@example.com" + suffix
    scanner = DLPScanner()
    redacted, findings = scanner.redact(text)
    assert redacted == "[REDACTED:EMAIL]" + suffix
    assert [item.finding_type for item in findings] == [FindingType.EMAIL]
    encoded = _base64(text)
    encoded_result, encoded_findings = scanner.redact(f"({encoded})")
    assert encoded_result == "([REDACTED:EMAIL])"
    assert [item.finding_type for item in encoded_findings] == [FindingType.EMAIL]


@pytest.mark.parametrize("suffix", [".123", ".com7", ".invalid_label", "-suffix", "_suffix", "..example", ".đề", "7"])
def test_email_does_not_redact_only_prefix_of_invalid_domain(suffix):
    text = "person@example.com" + suffix
    result, findings = DLPScanner().redact(text)
    assert result == text
    assert not findings


def test_email_valid_multilabel_domain_is_redacted_completely_before_fullstop():
    result, findings = DLPScanner().redact("Contact person@mail.example.co.uk.")
    assert result == "Contact [REDACTED:EMAIL]."
    assert [item.finding_type for item in findings] == [FindingType.EMAIL]


def test_different_encoded_occurrences_and_adjacent_plain_secret_are_all_removed():
    encoded = _base64("person@example.com")
    source = f"({encoded}) {_percent('other@example.com')} ({encoded}) password:last-secret"
    result, findings = DLPScanner().redact(source)
    assert encoded not in result and "last-secret" not in result
    assert "example" not in result and "%40" not in result
    emails = next(item for item in findings if item.finding_type is FindingType.EMAIL)
    assert emails.count == 3


@pytest.mark.parametrize(
    "text, term, expected",
    [
        ("Straße ORION end", "ORION", "Straße [REDACTED:CUSTOM_DICTIONARY] end"),
        ("STRASSE then Straße", "strasse", "[REDACTED:CUSTOM_DICTIONARY] then [REDACTED:CUSTOM_DICTIONARY]"),
        ("İ prefix ORION", "orion", "İ prefix [REDACTED:CUSTOM_DICTIONARY]"),
        ("ßßß ORION", "orion", "ßßß [REDACTED:CUSTOM_DICTIONARY]"),
    ],
)
def test_dictionary_casefold_expansion_maps_to_real_source_offsets(text, term, expected):
    scanner = DLPScanner(custom_dictionaries={"sensitive-name": [term]})
    result, findings = scanner.redact(text)
    assert result == expected
    assert findings and "sensitive-name" not in repr(findings)
    encoded, encoded_findings = scanner.redact(_base64(text))
    assert encoded == "[REDACTED:CUSTOM_DICTIONARY]"
    assert encoded_findings


def test_dictionary_partial_casefold_character_match_still_redacts_whole_character():
    scanner = DLPScanner(custom_dictionaries=[CustomDictionary("terms", ["s"], whole_word=False)])
    assert scanner.redact("ß")[0] == "[REDACTED:CUSTOM_DICTIONARY]"


@pytest.mark.parametrize("encoded", ["bi&#769; m&#7853;t", "bi%CC%81 m%E1%BA%ADt"])
def test_decoded_combining_marks_cannot_evade_normalized_dictionary(encoded):
    scanner = DLPScanner(custom_dictionaries={"phrases": ["bí mật"]})
    redacted, findings = scanner.redact(f"before {encoded} after")
    assert redacted == "[REDACTED:CUSTOM_DICTIONARY]"
    assert findings[0].finding_type is FindingType.CUSTOM_DICTIONARY


@pytest.mark.parametrize("label", ["password", "api_key"])
@pytest.mark.parametrize("delimiter", ['"', "'"])
def test_incomplete_quoted_assignment_does_not_backtrack_exponentially(label, delimiter):
    # Overlapping alternatives for backslash used to permit 2**N backtracking
    # before the unquoted fallback. No fragile wall-clock assertion is needed.
    payload = label + "=" + delimiter + "\\" * 500
    decision = DLPScanner().evaluate(payload)
    assert decision.action is DLPAction.BLOCK


@pytest.mark.parametrize(
    "text",
    [
        "Regular internationalization documentation and compatibility information.",
        "Giải thích nguyên tắc phân quyền, bảo vệ dữ liệu và xác thực.",
        "https://example.com/docs?title=Defense%20in%20Depth&lang=vi",
        "Some HTML: &lt;b&gt;hello&lt;/b&gt; &amp; ordinary text.",
        _base64("Hello world! This is ordinary educational text."),
        _base64("Giải thích cách kiểm tra dữ liệu."),
        "SGVsbG8gd29ybGQh%% invalid%ZZ and %FF invalid UTF-8",
        "A" * 100,
        "&#not-an-entity; %1 %XY",
    ],
)
def test_benign_and_malformed_encoded_content_is_not_rewritten(text):
    redacted, findings = DLPScanner().redact(text)
    assert redacted == text
    assert not findings


def test_nested_encoding_beyond_depth_is_blocked_without_disclosing_content():
    payload = "password:deep-secret"
    for _ in range(dlp.MAX_DECODE_DEPTH + 2):
        payload = _base64(payload)
    scanner = DLPScanner()
    decision = scanner.evaluate(payload)
    assert decision.action is DLPAction.BLOCK
    assert {item.finding_type for item in decision.findings} == {FindingType.INSPECTION_LIMIT}
    assert scanner.redact(payload)[0] == "[REDACTED:INSPECTION_LIMIT]"
    assert payload not in json.dumps(decision.safe_report())


@pytest.mark.parametrize("budget_name, budget", [("MAX_DECODED_VIEWS", 2), ("MAX_DECODED_CHARACTERS", 100)])
def test_work_budget_never_passes_uninspected_encoded_suffix(monkeypatch, budget_name, budget):
    monkeypatch.setattr(dlp, budget_name, budget)
    tokens = [_base64(f"harmless educational sentence {index}") for index in range(4)]
    secret = _base64("password:late-secret")
    source = " ".join([*tokens, secret])
    scanner = DLPScanner()
    decision = scanner.evaluate(source)
    assert decision.action is DLPAction.BLOCK
    assert FindingType.INSPECTION_LIMIT in {item.finding_type for item in decision.findings}
    redacted, _ = scanner.redact(source)
    assert secret not in redacted


def test_oversized_scan_is_blocked_and_entire_payload_is_withheld():
    payload = "x" * (dlp.MAX_SCAN_CHARACTERS + 1)
    scanner = DLPScanner()
    assert scanner.evaluate(payload).action is DLPAction.BLOCK
    assert scanner.redact(payload)[0] == "[REDACTED:INSPECTION_LIMIT]"


class _RecordingProvider:
    def __init__(self, response="Safe answer"):
        self.calls = []
        self.response = response

    def generate(self, prompt, **kwargs):
        self.calls.append((prompt, kwargs))
        return self.response


def _service(settings, response="Safe answer"):
    service = AIService(replace(settings, google_genai_api_key=""))
    provider = _RecordingProvider(response)
    service._client = provider
    return service, provider


def test_demo_sample_redacts_plain_and_encoded_email_before_offline_echo(settings):
    email = "sinhvien@example.com"
    encoded = _base64(email)
    sample = f"Email mẫu của tôi: {email}. Chuỗi Base64: {encoded}"
    service = AIService(replace(settings, google_genai_api_key="", allow_demo_ai=True))
    response, labels = service.generate(sample, [], allow_external_ai=False)
    assert response.startswith("[DEMO AI]")
    assert response.count("[REDACTED:EMAIL]") == 2
    assert email not in response and encoded not in response
    assert labels == ["email"]


def test_punctuated_email_removed_from_provider_prompt_history_and_output(settings):
    email = "sinhvien@example.com"
    encoded = _base64(email + ".")
    service, provider = _service(settings, f"Contact {email}. Encoded: ({encoded})")
    response, labels = service.generate(
        f"Email mẫu của tôi: {email}. Chuỗi Base64: {encoded}",
        [{"role": "user", "content": f"Previous email {email}."}],
        allow_external_ai=True,
    )
    assert len(provider.calls) == 1
    prompt = provider.calls[0][0]
    assert prompt.count("[REDACTED:EMAIL]") == 3
    assert response.count("[REDACTED:EMAIL]") == 2
    assert email not in prompt + response and encoded not in prompt + response
    assert labels == ["email"]


def test_encoded_credential_rejects_before_history_decryption_and_provider_call(settings):
    service, provider = _service(settings)

    def forbidden_history_load():
        pytest.fail("Rejected current prompt must not decrypt history")

    with pytest.raises(DLPPolicyViolation) as error:
        service.generate(_base64("password:current-secret"), forbidden_history_load, allow_external_ai=True)
    assert error.value.action is DLPAction.BLOCK
    assert not provider.calls
    assert "current-secret" not in str(error.value)


def test_encoded_credential_in_history_blocks_provider_call(settings):
    service, provider = _service(settings)
    with pytest.raises(DLPPolicyViolation):
        service.generate(
            "Explain this",
            [{"role": "user", "content": _percent("password:historical-secret")}],
            allow_external_ai=True,
        )
    assert not provider.calls


def test_encoded_pii_is_removed_from_current_prompt_and_history_before_egress(settings):
    service, provider = _service(settings)
    email1, email2 = _base64("first@example.com"), _entities("other@example.com")
    response, labels = service.generate(
        f"Contact ({email1})",
        [{"role": "assistant", "content": f"Contact {email2}"}],
        allow_external_ai=True,
    )
    assert response == "Safe answer"
    assert labels == ["email"]
    assert len(provider.calls) == 1
    prompt = provider.calls[0][0]
    assert email1 not in prompt and email2 not in prompt
    assert "example.com" not in prompt
    assert prompt.count("[REDACTED:EMAIL]") == 2


def test_encoded_custom_terms_apply_to_provider_response(settings):
    encoded = _base64("ORION")
    service, _ = _service(replace(settings, dlp_custom_terms=("ORION",)), f"Project ({encoded})")
    response, labels = service.generate("Hello", [], allow_external_ai=True)
    assert response == "Project ([REDACTED:CUSTOM_DICTIONARY])"
    assert labels == ["dữ liệu nội bộ"]


@pytest.mark.parametrize(
    "provider_response, expected_label",
    [
        ("a " * 3990 + _base64("password:" + "Q" * 200), "mật khẩu"),
        ("a " * 3990 + "-----BEGIN PRIVATE KEY-----\nZXhhbXBsZS1rZXk=\n-----END PRIVATE KEY-----", "khóa riêng tư"),
    ],
)
def test_output_secret_straddling_display_limit_is_removed_before_truncation(settings, provider_response, expected_label):
    service, provider = _service(settings, provider_response)
    response, labels = service.generate("Hello", [], allow_external_ai=True)
    assert len(provider.calls) == 1
    assert len(response) <= 8000
    assert response.startswith("a " * 3990)
    assert "-----BEGIN" not in response
    assert "cGFzc3dvcmQ" not in response
    assert expected_label in labels


@pytest.mark.parametrize("response", [None, b"secret-bytes", {"secret": "private-value"}, "secret-prefix" + "x" * MAX_PROVIDER_RESPONSE_CHARACTERS])
def test_malformed_or_oversized_provider_response_fails_closed_without_logs(settings, caplog, response):
    service, _ = _service(settings, response)
    with caplog.at_level(logging.ERROR, logger="secure_chat.ai"):
        with pytest.raises(AIProviderError) as error:
            service.generate("Hello", [], allow_external_ai=True)
    assert str(error.value) == AI_UNAVAILABLE_MESSAGE
    assert "secret-prefix" not in caplog.text
    assert "secret-bytes" not in caplog.text
    assert "private-value" not in caplog.text


def _session_with_consent(client, username):
    token = register_and_login(client, username)
    headers = {"Authorization": f"Bearer {token}"}
    consent = client.patch("/api/auth/ai-consent", headers=headers, json={"ai_data_consent": True})
    assert consent.status_code == 200
    session = client.post("/api/sessions", headers=headers, json={"title": "Boundary review"})
    assert session.status_code == 201
    return headers, session.json()["id"]


def test_api_blocks_encoded_secret_audits_categories_and_persists_no_messages(client, app):
    provider = _RecordingProvider()
    app.state.chat_service.ai._client = provider
    headers, session_id = _session_with_consent(client, "encoded-block")
    encoded = _base64("password:synthetic-encoded-secret")
    response = client.post(
        f"/api/sessions/{session_id}/messages", headers=headers, json={"content": encoded}
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "dlp_block"
    assert not provider.calls
    with app.state.database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(SecureMessage)) == 0
        event = db.scalar(select(AuditEvent).where(AuditEvent.event_type == "dlp.policy"))
        assert event is not None and event.outcome == "blocked"
        audit_details = event.details_json
    assert "mật khẩu" in json.loads(audit_details)["categories"]
    assert encoded not in response.text + audit_details
    assert "synthetic-encoded-secret" not in response.text + audit_details


def test_api_oversized_provider_response_returns_503_and_persists_no_messages(client, app):
    provider = _RecordingProvider("x" * (MAX_PROVIDER_RESPONSE_CHARACTERS + 1))
    app.state.chat_service.ai._client = provider
    headers, session_id = _session_with_consent(client, "oversized-output")
    response = client.post(
        f"/api/sessions/{session_id}/messages", headers=headers, json={"content": "Hello"}
    )
    assert response.status_code == 503
    assert response.json()["detail"] == AI_UNAVAILABLE_MESSAGE
    assert response.headers["Retry-After"] == "30"
    assert len(provider.calls) == 1
    with app.state.database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(SecureMessage)) == 0
