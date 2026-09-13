"""Adversarial, false-positive, policy, and output tests for formal DLP."""

from __future__ import annotations

import json

import pytest

from src.app.dlp import (
    CustomDictionary,
    DataClass,
    DLPAction,
    DLPPolicy,
    DLPScanner,
    FindingType,
    is_luhn_valid,
    normalize_text,
)


def _types(scanner: DLPScanner, text: str) -> set[FindingType]:
    return {finding.finding_type for finding in scanner.scan(text)}


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ("password: Correct-Horse-Battery-Staple", FindingType.SECRET),
        ("Authorization: Bearer abcdefghijklmnop.qrstuvwx", FindingType.BEARER_TOKEN),
        (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
            FindingType.JWT,
        ),
        (
            "-----BEGIN PRIVATE KEY-----\nZXhhbXBsZS1rZXktbWF0ZXJpYWw=\n"
            "-----END PRIVATE KEY-----",
            FindingType.PRIVATE_KEY,
        ),
        ("api_key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWX1234567", FindingType.API_KEY),
        ("OpenAI sk-proj-abcdefghijklmnopqrstuvwx_123456", FindingType.API_KEY),
    ],
)
def test_credential_detectors(payload: str, expected: FindingType):
    assert expected in _types(DLPScanner(), payload)


def test_nfkc_and_zero_width_normalization_defeat_visual_evasion():
    # Full-width "api_key=" plus zero-width characters inside both label and value.
    payload = "ａｐｉ＿ｋｅｙ＝AIzaSyABCDE\u200bFGHIJKLMNO\ufeffPQRSTUVWX1234567"
    scanner = DLPScanner()
    redacted, findings = scanner.redact(payload)

    assert normalize_text("Ｂｅａｒ\u200bｅｒ") == "Bearer"
    assert FindingType.API_KEY in {item.finding_type for item in findings}
    assert "AIza" not in redacted
    assert "\u200b" not in redacted and "\ufeff" not in redacted


@pytest.mark.parametrize(
    "number",
    [
        "4111 1111 1111 1111",
        "5555-5555-5555-4444",
        "378282246310005",
    ],
)
def test_payment_card_is_detected_only_after_luhn_validation(number: str):
    scanner = DLPScanner()
    assert is_luhn_valid(number)
    assert FindingType.PAYMENT_CARD in _types(scanner, f"thẻ: {number}")


@pytest.mark.parametrize(
    "number",
    [
        "4111 1111 1111 1112",  # one changed check digit
        "1234 5678 9012 3456",
        "0000 0000 0000 0000",
    ],
)
def test_invalid_luhn_candidates_are_not_classified_as_cards(number: str):
    scanner = DLPScanner()
    assert not is_luhn_valid(number)
    assert FindingType.PAYMENT_CARD not in _types(scanner, number)
    redacted, findings = scanner.redact(number)
    assert redacted == number
    assert findings == ()


def test_vietnamese_personal_identifiers_are_distinguished():
    payload = (
        "Email: an.nguyen@phenikaa-uni.edu.vn; điện thoại 0912 345 678; "
        "CCCD 001203004567; MST: 0100109106"
    )
    types = _types(DLPScanner(), payload)
    assert types >= {
        FindingType.EMAIL,
        FindingType.PHONE,
        FindingType.CCCD,
        FindingType.TAX_ID,
    }


def test_health_detector_requires_personal_or_structured_context():
    scanner = DLPScanner()
    assert FindingType.HEALTH_DATA in _types(scanner, "Mẹ tôi đang điều trị ung thư.")
    assert FindingType.HEALTH_DATA in _types(scanner, "Chẩn đoán: tiểu đường type 2")

    # Technical/educational health vocabulary alone is not personal health data.
    assert FindingType.HEALTH_DATA not in _types(scanner, "Cấu hình health check endpoint")
    assert FindingType.HEALTH_DATA not in _types(scanner, "Bài giảng tổng quan về ung thư")


def test_custom_dictionary_is_normalized_and_whole_word_by_default():
    dictionary = CustomDictionary(
        "project-codenames",
        ["DỰ ÁN ORION", "ACME-OMEGA"],
        data_class=DataClass.CONFIDENTIAL,
    )
    scanner = DLPScanner(custom_dictionaries=[dictionary])

    redacted, findings = scanner.redact("Kế hoạch DỰ\u200b ÁN ORION cần được giữ kín")
    assert FindingType.CUSTOM_DICTIONARY in {item.finding_type for item in findings}
    assert "ORION" not in redacted
    assert scanner.scan("tiền tố ACME-OMEGAX hậu tố") == ()


def test_mapping_is_a_shortcut_for_custom_dictionaries():
    scanner = DLPScanner(custom_dictionaries={"tenant-terms": ["Blue Phoenix"]})
    redacted, findings = scanner.redact("Release Blue Phoenix vào thứ Hai")
    assert "Blue Phoenix" not in redacted
    assert findings[0].finding_type is FindingType.CUSTOM_DICTIONARY


@pytest.mark.parametrize(
    ("data_class", "expected"),
    [
        (DataClass.PUBLIC, DLPAction.ALLOW),
        (DataClass.INTERNAL, DLPAction.CONFIRM),
        (DataClass.CONFIDENTIAL, DLPAction.REDACT),
        (DataClass.HIGHLY_CONFIDENTIAL, DLPAction.BLOCK),
        (DataClass.E2EE_PRIVATE, DLPAction.LOCAL_ONLY),
    ],
)
def test_default_five_level_policy(data_class: DataClass, expected: DLPAction):
    decision = DLPScanner().evaluate("Nội dung thông thường", data_class=data_class)
    assert decision.action is expected
    assert decision.may_leave_boundary is (expected in {DLPAction.ALLOW, DLPAction.REDACT})
    if expected in {DLPAction.CONFIRM, DLPAction.BLOCK, DLPAction.LOCAL_ONLY}:
        assert decision.output_text is None


def test_internal_confirmation_must_be_explicit():
    scanner = DLPScanner()
    pending = scanner.evaluate("kế hoạch họp nội bộ", data_class="internal")
    approved = scanner.evaluate("kế hoạch họp nội bộ", data_class="internal", confirmed=True)
    assert pending.action is DLPAction.CONFIRM
    assert pending.output_text is None
    assert approved.action is DLPAction.ALLOW
    assert approved.output_text == "kế hoạch họp nội bộ"


def test_detector_can_raise_but_never_downgrade_declared_class():
    scanner = DLPScanner()
    secret = scanner.evaluate("password: never-log-this", data_class=DataClass.PUBLIC)
    e2ee = scanner.evaluate("hello", data_class=DataClass.E2EE_PRIVATE)
    assert secret.effective_data_class is DataClass.HIGHLY_CONFIDENTIAL
    assert secret.action is DLPAction.BLOCK
    assert secret.output_text is None
    assert e2ee.effective_data_class is DataClass.E2EE_PRIVATE
    assert e2ee.action is DLPAction.LOCAL_ONLY


def test_confidential_output_is_redacted_before_egress():
    secret_email = "alice.private@example.org"
    decision = DLPScanner().evaluate(f"Liên hệ {secret_email}")
    assert decision.action is DLPAction.REDACT
    assert decision.output_text is not None
    assert secret_email not in decision.output_text
    assert "[REDACTED:EMAIL]" in decision.output_text


def test_reports_and_reprs_never_contain_matched_values():
    values = [
        "vault-password-987654",
        "security-team@example.org",
        "Project Obsidian",
    ]
    scanner = DLPScanner(
        custom_dictionaries=[CustomDictionary(values[2], [values[2]])]
    )
    decision = scanner.evaluate(
        f"password: {values[0]}; email {values[1]}; codename {values[2]}"
    )
    serialized_report = json.dumps(decision.safe_report(), ensure_ascii=False)
    public_representations = serialized_report + repr(decision) + repr(decision.findings)

    for value in values:
        assert value not in public_representations
    assert set(decision.safe_report()) == {
        "action",
        "declared_data_class",
        "effective_data_class",
        "requires_confirmation",
        "may_leave_boundary",
        "finding_count",
        "findings",
    }
    assert all(not hasattr(item, "value") for item in decision.findings)


@pytest.mark.parametrize(
    "benign",
    [
        "Giải thích Defense in Depth và least privilege.",
        "Mã bài tập 21010999 và phiên bản 20260913.",
        "UUID 6f1c9d2e-1111-2222-3333-444455556666",
        "Số tham chiếu 999999999999 không phải CCCD.",
        "Điện thoại mẫu 0123456789 không còn là đầu số hợp lệ.",
        "Chuỗi 1234 5678 9012 3456 chỉ là dữ liệu kiểm thử.",
        "Cấu hình /health và health check cho load balancer.",
        "Tài liệu nói chung về diabetes và cancer.",
        "sketch-not-an-api-key",
        "header.payload.signature không phải JWT",
    ],
)
def test_false_positive_corpus_stays_clean(benign: str):
    assert DLPScanner().scan(benign) == ()


def test_policy_is_configurable_but_must_cover_every_class():
    actions = {item: DLPAction.BLOCK for item in DataClass}
    actions[DataClass.PUBLIC] = DLPAction.ALLOW
    policy = DLPPolicy(actions=actions)
    assert DLPScanner(policy=policy).evaluate("clean").action is DLPAction.ALLOW

    with pytest.raises(ValueError, match="thiếu data class"):
        DLPPolicy(actions={DataClass.PUBLIC: DLPAction.ALLOW})


def test_output_dlp_uses_same_boundary_scanner_as_input():
    """Provider output must not get a weaker detector than prompt input."""

    provider_output = "Tôi vô tình lặp lại token Bearer abcdefghijklmnopqrstuv"
    redacted, findings = DLPScanner().redact(provider_output)
    assert "abcdefghijklmnopqrstuv" not in redacted
    assert {item.finding_type for item in findings} == {FindingType.BEARER_TOKEN}
