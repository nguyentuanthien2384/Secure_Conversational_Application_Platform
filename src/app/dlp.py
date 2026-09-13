"""Formal data-loss-prevention scanning and policy decisions.

The module is deliberately independent from the HTTP and AI-provider layers.  It
can therefore be used at every trust-boundary (prompt input, provider output,
exports, and audit ingestion) without importing application configuration.

Security invariant: public findings and reports contain categories and counts,
never the text which triggered a detector.  Match spans live only in private,
short-lived objects used while producing a redacted payload.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum


class DataClass(str, Enum):
    """Data handling classes, ordered from least to most restrictive."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    HIGHLY_CONFIDENTIAL = "highly_confidential"
    E2EE_PRIVATE = "e2ee_private"


class DLPAction(str, Enum):
    """The only actions a DLP policy may return."""

    ALLOW = "allow"
    REDACT = "redact"
    CONFIRM = "confirm"
    BLOCK = "block"
    LOCAL_ONLY = "local_only"


class FindingType(str, Enum):
    """Stable, non-secret identifiers for detector results."""

    SECRET = "secret"
    JWT = "jwt"
    BEARER_TOKEN = "bearer_token"
    PRIVATE_KEY = "private_key"
    API_KEY = "api_key"
    EMAIL = "email"
    PHONE = "phone"
    PAYMENT_CARD = "payment_card"
    CCCD = "cccd"
    TAX_ID = "tax_id"
    HEALTH_DATA = "health_data"
    CUSTOM_DICTIONARY = "custom_dictionary"

    # Readable aliases for integrations which use broader terminology.
    CREDIT_CARD = "payment_card"
    NATIONAL_ID = "cccd"


class FindingSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Aliases make the public vocabulary convenient without creating competing
# representations of the same policy outcome.
Action = DLPAction
Decision = DLPAction
DataClassification = DataClass


_CLASS_RANK: dict[DataClass, int] = {
    DataClass.PUBLIC: 0,
    DataClass.INTERNAL: 1,
    DataClass.CONFIDENTIAL: 2,
    DataClass.HIGHLY_CONFIDENTIAL: 3,
    DataClass.E2EE_PRIVATE: 4,
}


_DEFAULT_CLASS_BY_FINDING: dict[FindingType, DataClass] = {
    FindingType.SECRET: DataClass.HIGHLY_CONFIDENTIAL,
    FindingType.JWT: DataClass.HIGHLY_CONFIDENTIAL,
    FindingType.BEARER_TOKEN: DataClass.HIGHLY_CONFIDENTIAL,
    FindingType.PRIVATE_KEY: DataClass.HIGHLY_CONFIDENTIAL,
    FindingType.API_KEY: DataClass.HIGHLY_CONFIDENTIAL,
    FindingType.EMAIL: DataClass.CONFIDENTIAL,
    FindingType.PHONE: DataClass.CONFIDENTIAL,
    FindingType.PAYMENT_CARD: DataClass.HIGHLY_CONFIDENTIAL,
    FindingType.CCCD: DataClass.HIGHLY_CONFIDENTIAL,
    FindingType.TAX_ID: DataClass.HIGHLY_CONFIDENTIAL,
    FindingType.HEALTH_DATA: DataClass.HIGHLY_CONFIDENTIAL,
    FindingType.CUSTOM_DICTIONARY: DataClass.CONFIDENTIAL,
}


_SEVERITY_BY_CLASS: dict[DataClass, FindingSeverity] = {
    DataClass.PUBLIC: FindingSeverity.LOW,
    DataClass.INTERNAL: FindingSeverity.LOW,
    DataClass.CONFIDENTIAL: FindingSeverity.HIGH,
    DataClass.HIGHLY_CONFIDENTIAL: FindingSeverity.CRITICAL,
    DataClass.E2EE_PRIVATE: FindingSeverity.CRITICAL,
}


_SAFE_LABELS: dict[FindingType, str] = {
    FindingType.SECRET: "Mật khẩu hoặc bí mật",
    FindingType.JWT: "JWT",
    FindingType.BEARER_TOKEN: "Bearer token",
    FindingType.PRIVATE_KEY: "Khóa riêng tư",
    FindingType.API_KEY: "API key hoặc access token",
    FindingType.EMAIL: "Địa chỉ email",
    FindingType.PHONE: "Số điện thoại",
    FindingType.PAYMENT_CARD: "Số thẻ thanh toán",
    FindingType.CCCD: "Số căn cước công dân",
    FindingType.TAX_ID: "Mã số thuế Việt Nam",
    FindingType.HEALTH_DATA: "Dữ liệu sức khỏe",
    FindingType.CUSTOM_DICTIONARY: "Từ điển dữ liệu tùy chỉnh",
}


@dataclass(frozen=True, slots=True)
class DLPFinding:
    """A safe, aggregated finding which is suitable for logs and API output.

    It intentionally has no ``value``, ``sample``, ``context``, or offset fields.
    Keeping even a short preview in an audit event would turn the audit system
    into a second data-leak channel.
    """

    finding_type: FindingType
    detector_id: str
    label: str
    data_class: DataClass
    severity: FindingSeverity
    count: int = 1

    @property
    def category(self) -> FindingType:
        """Compatibility name used by UI and SIEM adapters."""

        return self.finding_type

    def safe_dict(self) -> dict[str, str | int]:
        return {
            "type": self.finding_type.value,
            "detector": self.detector_id,
            "label": self.label,
            "data_class": self.data_class.value,
            "severity": self.severity.value,
            "count": self.count,
        }

    to_report = safe_dict


@dataclass(frozen=True, slots=True)
class DLPDecision:
    """Policy outcome plus an optional payload safe to cross the boundary."""

    action: DLPAction
    declared_data_class: DataClass
    effective_data_class: DataClass
    findings: tuple[DLPFinding, ...]
    output_text: str | None = field(default=None, repr=False)
    normalized: bool = True
    confirmed: bool = False

    @property
    def decision(self) -> DLPAction:
        return self.action

    @property
    def may_leave_boundary(self) -> bool:
        return self.action in {DLPAction.ALLOW, DLPAction.REDACT}

    @property
    def requires_confirmation(self) -> bool:
        return self.action is DLPAction.CONFIRM

    @property
    def blocked(self) -> bool:
        return self.action in {DLPAction.BLOCK, DLPAction.LOCAL_ONLY}

    def safe_report(self) -> dict[str, object]:
        """Return an audit/API report with no original or matched content."""

        return {
            "action": self.action.value,
            "declared_data_class": self.declared_data_class.value,
            "effective_data_class": self.effective_data_class.value,
            "requires_confirmation": self.requires_confirmation,
            "may_leave_boundary": self.may_leave_boundary,
            "finding_count": sum(item.count for item in self.findings),
            "findings": [item.safe_dict() for item in self.findings],
        }

    to_report = safe_report


@dataclass(frozen=True, slots=True)
class CustomDictionary:
    """Terms which are sensitive in one deployment (project names, codenames…)."""

    name: str
    terms: tuple[str, ...] = field(repr=False)
    data_class: DataClass = DataClass.CONFIDENTIAL
    whole_word: bool = True

    def __init__(
        self,
        name: str,
        terms: Iterable[str],
        data_class: DataClass | str = DataClass.CONFIDENTIAL,
        whole_word: bool = True,
    ) -> None:
        normalized_name = normalize_text(name).strip()
        if not normalized_name:
            raise ValueError("Tên từ điển không được để trống.")
        normalized_terms = tuple(
            dict.fromkeys(
                term
                for raw in terms
                if (term := normalize_text(str(raw)).strip())
            )
        )
        if not normalized_terms:
            raise ValueError("Từ điển DLP cần ít nhất một giá trị không rỗng.")
        object.__setattr__(self, "name", normalized_name)
        object.__setattr__(self, "terms", normalized_terms)
        object.__setattr__(self, "data_class", _coerce_data_class(data_class))
        object.__setattr__(self, "whole_word", bool(whole_word))


@dataclass(frozen=True, slots=True)
class DLPPolicy:
    """Handling action for each data class.

    The default follows the five-level policy in the project specification:
    public data may leave, internal data needs explicit confirmation,
    confidential data is redacted, highly-confidential data is blocked, and
    E2EE-private data never leaves the local trust boundary.
    """

    actions: Mapping[DataClass, DLPAction] = field(
        default_factory=lambda: {
            DataClass.PUBLIC: DLPAction.ALLOW,
            DataClass.INTERNAL: DLPAction.CONFIRM,
            DataClass.CONFIDENTIAL: DLPAction.REDACT,
            DataClass.HIGHLY_CONFIDENTIAL: DLPAction.BLOCK,
            DataClass.E2EE_PRIVATE: DLPAction.LOCAL_ONLY,
        },
        repr=False,
    )

    def __post_init__(self) -> None:
        normalized: dict[DataClass, DLPAction] = {}
        for raw_class, raw_action in self.actions.items():
            data_class = _coerce_data_class(raw_class)
            try:
                action = raw_action if isinstance(raw_action, DLPAction) else DLPAction(raw_action)
            except ValueError as exc:
                raise ValueError(f"Hành động DLP không hợp lệ: {raw_action!r}") from exc
            normalized[data_class] = action
        missing = set(DataClass) - set(normalized)
        if missing:
            values = ", ".join(sorted(item.value for item in missing))
            raise ValueError(f"Chính sách DLP thiếu data class: {values}")
        object.__setattr__(self, "actions", normalized)

    def action_for(self, data_class: DataClass | str) -> DLPAction:
        return self.actions[_coerce_data_class(data_class)]


@dataclass(frozen=True, slots=True)
class _DetectedSpan:
    start: int
    end: int
    finding_type: FindingType
    detector_id: str
    data_class: DataClass


Validator = Callable[[str], bool]


@dataclass(frozen=True, slots=True)
class _RegexRule:
    detector_id: str
    finding_type: FindingType
    pattern: re.Pattern[str]
    data_class: DataClass
    group: str | int = "value"
    validator: Validator | None = None


# NFKC defeats full-width and compatibility-character evasions.  Format
# controls and variation selectors are invisible in rendered text and are a
# common way to split credentials (``Be\u200barer`` or ``api\u200b_key``).
_VARIATION_SELECTOR_RANGES = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))


def _is_invisible_format_character(character: str) -> bool:
    codepoint = ord(character)
    return unicodedata.category(character) == "Cf" or any(
        start <= codepoint <= end for start, end in _VARIATION_SELECTOR_RANGES
    )


def normalize_text(text: str) -> str:
    """Canonicalize text for detection and remove invisible token splitters."""

    if not isinstance(text, str):
        raise TypeError("Nội dung DLP phải là chuỗi.")
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(char for char in normalized if not _is_invisible_format_character(char))


def _coerce_data_class(value: DataClass | str) -> DataClass:
    if isinstance(value, DataClass):
        return value
    try:
        return DataClass(str(value).strip().lower())
    except ValueError as exc:
        raise ValueError(f"Data class không hợp lệ: {value!r}") from exc


def _digits(value: str) -> str:
    return "".join(character for character in value if character.isdecimal())


def is_luhn_valid(value: str) -> bool:
    """Validate a 13–19 digit payment-card candidate before classifying it."""

    digits = _digits(value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        number = int(character)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        checksum += number
    return checksum % 10 == 0


def _valid_phone(value: str) -> bool:
    compact = re.sub(r"[\s.()/-]", "", value)
    if compact.startswith("+84"):
        compact = "0" + compact[3:]
    elif compact.startswith("84"):
        compact = "0" + compact[2:]
    if not compact.isdecimal() or len(set(compact)) == 1:
        return False
    if len(compact) == 10 and compact[:2] in {"03", "05", "07", "08", "09"}:
        return True
    return compact.startswith("02") and len(compact) in {10, 11}


_VN_PROVINCE_CODES = frozenset(
    """
    001 002 004 006 008 010 011 012 014 015 017 019 020 022 024 025 026 027
    030 031 033 034 035 036 037 038 040 042 044 045 046 048 049 051 052 054
    056 058 060 062 064 066 067 068 070 072 074 075 077 079 080 082 083 084
    086 087 089 091 092 093 094 095 096
    """.split()
)


def _valid_cccd(value: str) -> bool:
    digits = _digits(value)
    return len(digits) == 12 and digits[:3] in _VN_PROVINCE_CODES


def _valid_tax_id_checksum(value: str) -> bool:
    digits = _digits(value)
    if len(digits) == 13:
        digits = digits[:10]
    if len(digits) != 10 or len(set(digits)) == 1:
        return False
    weights = (31, 29, 23, 19, 17, 13, 7, 5, 3)
    expected = 10 - (
        sum(
            int(digit) * weight
            for digit, weight in zip(digits[:9], weights, strict=True)
        )
        % 11
    )
    if expected >= 10:
        expected = 0
    return int(digits[-1]) == expected


_FLAGS = re.IGNORECASE | re.UNICODE

_REGEX_RULES: tuple[_RegexRule, ...] = (
    _RegexRule(
        "secret.assignment",
        FindingType.SECRET,
        re.compile(
            r"\b(?:password|passwd|passphrase|pwd|mật\s*khẩu|client[_ -]?secret|"
            r"private[_ -]?secret|secret)\s*(?:is|là)?\s*[:=]\s*"
            r"(?P<value>\"(?:\\.|[^\"\r\n]){4,}\"|'(?:\\.|[^'\r\n]){4,}'|[^\s,;]{4,})",
            _FLAGS,
        ),
        DataClass.HIGHLY_CONFIDENTIAL,
    ),
    _RegexRule(
        "token.bearer",
        FindingType.BEARER_TOKEN,
        re.compile(r"\bbearer\s*[:=]?\s+(?P<value>[A-Za-z0-9._~+/-]{8,}=*)", _FLAGS),
        DataClass.HIGHLY_CONFIDENTIAL,
    ),
    _RegexRule(
        "token.jwt",
        FindingType.JWT,
        re.compile(
            r"(?<![A-Za-z0-9_-])(?P<value>eyJ[A-Za-z0-9_-]{5,}\."
            r"[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{2,})(?![A-Za-z0-9_-])"
        ),
        DataClass.HIGHLY_CONFIDENTIAL,
    ),
    _RegexRule(
        "key.private_pem",
        FindingType.PRIVATE_KEY,
        re.compile(
            r"(?P<value>-----BEGIN (?P<key_kind>(?:RSA |EC |OPENSSH )?PRIVATE KEY)-----"
            r"[\s\S]*?-----END (?P=key_kind)-----)",
            _FLAGS,
        ),
        DataClass.HIGHLY_CONFIDENTIAL,
    ),
    _RegexRule(
        "api_key.assignment",
        FindingType.API_KEY,
        re.compile(
            r"\b(?:api[_ -]?key|x-api-key|access[_ -]?token|refresh[_ -]?token|"
            r"auth[_ -]?token|google[_ -]?api[_ -]?key)\s*[:=]\s*"
            r"(?P<value>\"(?:\\.|[^\"\r\n]){6,}\"|'(?:\\.|[^'\r\n]){6,}'|[^\s,;]{6,})",
            _FLAGS,
        ),
        DataClass.HIGHLY_CONFIDENTIAL,
    ),
    _RegexRule(
        "api_key.known_format",
        FindingType.API_KEY,
        re.compile(
            r"(?<![A-Za-z0-9_-])(?P<value>(?:AIza[0-9A-Za-z_-]{30,}|"
            r"(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{30,255}|"
            r"github_pat_[A-Za-z0-9_]{30,255}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|"
            r"xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{16,}))"
            r"(?![A-Za-z0-9_-])"
        ),
        DataClass.HIGHLY_CONFIDENTIAL,
    ),
    _RegexRule(
        "pii.email",
        FindingType.EMAIL,
        re.compile(
            r"(?<![\w.+-])(?P<value>[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
            r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
            r"[A-Za-z]{2,63})(?![\w.-])"
        ),
        DataClass.CONFIDENTIAL,
    ),
    _RegexRule(
        "pii.vn_phone",
        FindingType.PHONE,
        re.compile(
            r"(?<![\d+])(?P<value>(?:\+?84|0)(?:[\s.()/-]?\d){9,10})(?!\d)"
        ),
        DataClass.CONFIDENTIAL,
        validator=_valid_phone,
    ),
    _RegexRule(
        "payment_card.luhn",
        FindingType.PAYMENT_CARD,
        re.compile(r"(?<!\d)(?P<value>\d(?:[ -]?\d){12,18})(?!\d)"),
        DataClass.HIGHLY_CONFIDENTIAL,
        validator=is_luhn_valid,
    ),
    _RegexRule(
        "vn.cccd.context",
        FindingType.CCCD,
        re.compile(
            r"\b(?:cccd|căn\s*cước(?:\s*công\s*dân)?|citizen\s+id)"
            r"\s*(?:số|number|no\.?|#)?\s*[:=.-]?\s*"
            r"(?P<value>\d(?:[ .-]?\d){11})(?!\d)",
            _FLAGS,
        ),
        DataClass.HIGHLY_CONFIDENTIAL,
        validator=lambda value: len(_digits(value)) == 12,
    ),
    _RegexRule(
        "vn.cccd.structure",
        FindingType.CCCD,
        re.compile(r"(?<!\d)(?P<value>\d{12})(?!\d)"),
        DataClass.HIGHLY_CONFIDENTIAL,
        validator=_valid_cccd,
    ),
    _RegexRule(
        "vn.tax_id.context",
        FindingType.TAX_ID,
        re.compile(
            r"\b(?:mã\s*số\s*thuế|ma\s*so\s*thue|mst|tax(?:payer)?[_ -]?id)"
            r"\s*[:=#.-]?\s*(?P<value>\d{10}(?:-\d{3})?)(?!\d)",
            _FLAGS,
        ),
        DataClass.HIGHLY_CONFIDENTIAL,
    ),
    _RegexRule(
        "vn.tax_id.checksum",
        FindingType.TAX_ID,
        re.compile(r"(?<!\d)(?P<value>\d{10}(?:-\d{3})?)(?!\d)"),
        DataClass.HIGHLY_CONFIDENTIAL,
        validator=_valid_tax_id_checksum,
    ),
)


_HEALTH_FIELD_RE = re.compile(
    r"\b(?:chẩn\s*đoán|chan\s*doan|bệnh\s*án|benh\s*an|kết\s*quả\s*xét\s*nghiệm|"
    r"ket\s*qua\s*xet\s*nghiem|đơn\s*thuốc|don\s*thuoc|diagnosis|medical[_ ]?record|"
    r"lab[_ ]?result|prescription|blood[_ ]?type)\s*[:=]\s*"
    r"(?P<value>[^\r\n;]{2,180})",
    _FLAGS,
)

_HEALTH_TERM_RE = re.compile(
    r"\b(?:hiv|aids|ung\s*thư|ung\s*thu|tiểu\s*đường|tieu\s*duong|"
    r"cao\s*huyết\s*áp|cao\s*huyet\s*ap|huyết\s*áp|huyet\s*ap|đường\s*huyết|"
    r"duong\s*huyet|thai\s*kỳ|thai\s*ky|dị\s*ứng|di\s*ung|hen\s*suyễn|"
    r"hen\s*suyen|viêm\s*gan|viem\s*gan|lao\s*phổi|lao\s*phoi|"
    r"trầm\s*cảm|tram\s*cam|rối\s*loạn\s*lo\s*âu|roi\s*loan\s*lo\s*au|"
    r"diabetes|cancer|hypertension|blood\s*pressure|blood\s*sugar|pregnan(?:t|cy)|"
    r"allerg(?:y|ic)|asthma|hepatitis|tuberculosis|depression|anxiety\s*disorder|"
    r"icd[- ]?10\s*[:#]?\s*[a-z]\d{2}(?:\.\d{1,4})?)\b",
    _FLAGS,
)

_PERSONAL_HEALTH_CONTEXT_RE = re.compile(
    r"\b(?:tôi|toi|mình|minh|em|anh|chị|chi|mẹ\s*tôi|me\s*toi|bố\s*tôi|bo\s*toi|"
    r"bệnh\s*nhân|benh\s*nhan|người\s*bệnh|nguoi\s*benh|hồ\s*sơ\s*của|"
    r"ho\s*so\s*cua|my|i\s+(?:have|am|was)|patient|the\s+patient|medical\s+record|"
    r"diagnosed\s+with|tested\s+positive|prescribed)\b",
    _FLAGS,
)


def _overlap(first: _DetectedSpan, second: _DetectedSpan) -> bool:
    return first.start < second.end and second.start < first.end


class DLPScanner:
    """Normalize, detect, redact, and apply the formal DLP policy."""

    def __init__(
        self,
        *,
        policy: DLPPolicy | None = None,
        custom_dictionaries: (
            Mapping[str, Iterable[str]] | Sequence[CustomDictionary] | None
        ) = None,
    ) -> None:
        self.policy = policy or DLPPolicy()
        dictionaries: list[CustomDictionary] = []
        if isinstance(custom_dictionaries, Mapping):
            dictionaries.extend(
                CustomDictionary(name=name, terms=terms)
                for name, terms in custom_dictionaries.items()
            )
        elif custom_dictionaries:
            for dictionary in custom_dictionaries:
                if not isinstance(dictionary, CustomDictionary):
                    raise TypeError("custom_dictionaries phải chứa CustomDictionary.")
                dictionaries.append(dictionary)
        self._custom_dictionaries = tuple(dictionaries)

    @staticmethod
    def normalize(text: str) -> str:
        return normalize_text(text)

    def _regex_spans(self, text: str) -> list[_DetectedSpan]:
        spans: list[_DetectedSpan] = []
        for rule in _REGEX_RULES:
            for match in rule.pattern.finditer(text):
                value = match.group(rule.group)
                if rule.validator is not None and not rule.validator(value):
                    continue
                start, end = match.span(rule.group)
                spans.append(
                    _DetectedSpan(
                        start=start,
                        end=end,
                        finding_type=rule.finding_type,
                        detector_id=rule.detector_id,
                        data_class=rule.data_class,
                    )
                )
        return spans

    @staticmethod
    def _health_spans(text: str) -> list[_DetectedSpan]:
        spans: list[_DetectedSpan] = []
        for match in _HEALTH_FIELD_RE.finditer(text):
            start, end = match.span("value")
            spans.append(
                _DetectedSpan(
                    start,
                    end,
                    FindingType.HEALTH_DATA,
                    "health.structured_context",
                    DataClass.HIGHLY_CONFIDENTIAL,
                )
            )
        for match in _HEALTH_TERM_RE.finditer(text):
            # Health vocabulary is not personal data by itself.  Requiring a
            # nearby subject avoids flagging educational content and common
            # phrases such as "health check endpoint".
            window = text[max(0, match.start() - 96) : min(len(text), match.end() + 96)]
            if not _PERSONAL_HEALTH_CONTEXT_RE.search(window):
                continue
            spans.append(
                _DetectedSpan(
                    match.start(),
                    match.end(),
                    FindingType.HEALTH_DATA,
                    "health.personal_context",
                    DataClass.HIGHLY_CONFIDENTIAL,
                )
            )
        return spans

    def _dictionary_spans(self, text: str) -> list[_DetectedSpan]:
        spans: list[_DetectedSpan] = []
        folded_text = text.casefold()
        for dictionary in self._custom_dictionaries:
            # A short opaque detector id distinguishes dictionaries without
            # putting a potentially sensitive dictionary name in reports.
            fingerprint = hashlib.sha256(dictionary.name.encode("utf-8")).hexdigest()[:12]
            detector_id = f"custom_dictionary.{fingerprint}"
            for term in dictionary.terms:
                folded_term = term.casefold()
                cursor = 0
                while True:
                    start = folded_text.find(folded_term, cursor)
                    if start < 0:
                        break
                    end = start + len(folded_term)
                    cursor = max(end, start + 1)
                    if dictionary.whole_word:
                        left_word = start > 0 and (
                            folded_text[start - 1].isalnum() or folded_text[start - 1] == "_"
                        )
                        right_word = end < len(folded_text) and (
                            folded_text[end].isalnum() or folded_text[end] == "_"
                        )
                        if left_word or right_word:
                            continue
                    spans.append(
                        _DetectedSpan(
                            start,
                            end,
                            FindingType.CUSTOM_DICTIONARY,
                            detector_id,
                            dictionary.data_class,
                        )
                    )
        return spans

    @staticmethod
    def _deduplicate_and_disambiguate(spans: Iterable[_DetectedSpan]) -> list[_DetectedSpan]:
        unique = {
            (item.start, item.end, item.finding_type, item.detector_id, item.data_class): item
            for item in spans
            if item.end > item.start
        }
        result = list(unique.values())
        # A ten-digit Vietnamese tax id can resemble a mobile number.  Explicit
        # or checksum-valid tax-id evidence wins over the generic phone shape.
        tax_spans = [item for item in result if item.finding_type is FindingType.TAX_ID]
        result = [
            item
            for item in result
            if not (
                item.finding_type is FindingType.PHONE
                and any(_overlap(item, tax_span) for tax_span in tax_spans)
            )
        ]
        return sorted(result, key=lambda item: (item.start, item.end, item.finding_type.value))

    def _detect_spans(self, normalized_text: str) -> list[_DetectedSpan]:
        return self._deduplicate_and_disambiguate(
            [
                *self._regex_spans(normalized_text),
                *self._health_spans(normalized_text),
                *self._dictionary_spans(normalized_text),
            ]
        )

    @staticmethod
    def _safe_findings(spans: Iterable[_DetectedSpan]) -> tuple[DLPFinding, ...]:
        # Multiple detectors may corroborate one value (for example an API-key
        # assignment whose value also has a known provider prefix).  Count that
        # as one occurrence, not two findings.
        occurrences = {
            (item.start, item.end, item.finding_type, item.data_class): item
            for item in spans
        }
        counts = Counter(
            (item.finding_type, item.data_class) for item in occurrences.values()
        )
        detector_ids: dict[tuple[FindingType, DataClass], set[str]] = {}
        for item in occurrences.values():
            detector_ids.setdefault((item.finding_type, item.data_class), set()).add(
                item.detector_id
            )
        findings = [
            DLPFinding(
                finding_type=finding_type,
                detector_id=(
                    next(iter(ids))
                    if len(ids := detector_ids[(finding_type, data_class)]) == 1
                    else f"{finding_type.value}.multiple"
                ),
                label=_SAFE_LABELS[finding_type],
                data_class=data_class,
                severity=_SEVERITY_BY_CLASS[data_class],
                count=count,
            )
            for (finding_type, data_class), count in counts.items()
        ]
        return tuple(
            sorted(
                findings,
                key=lambda item: (
                    -_CLASS_RANK[item.data_class],
                    item.finding_type.value,
                    item.detector_id,
                ),
            )
        )

    @staticmethod
    def _redact_spans(text: str, spans: Iterable[_DetectedSpan]) -> str:
        ordered = sorted(spans, key=lambda item: (item.start, item.end))
        if not ordered:
            return text

        merged: list[tuple[int, int, set[FindingType]]] = []
        for span in ordered:
            if not merged or span.start > merged[-1][1]:
                merged.append((span.start, span.end, {span.finding_type}))
                continue
            start, end, types = merged[-1]
            types.add(span.finding_type)
            merged[-1] = (start, max(end, span.end), types)

        chunks: list[str] = []
        cursor = 0
        for start, end, types in merged:
            chunks.append(text[cursor:start])
            category = "+".join(sorted(item.value.upper() for item in types))
            chunks.append(f"[REDACTED:{category}]")
            cursor = end
        chunks.append(text[cursor:])
        return "".join(chunks)

    def scan(self, text: str) -> tuple[DLPFinding, ...]:
        """Return safe findings; no match value or surrounding context escapes."""

        normalized = normalize_text(text)
        return self._safe_findings(self._detect_spans(normalized))

    detect = scan

    def redact(self, text: str) -> tuple[str, tuple[DLPFinding, ...]]:
        """Redact every finding, independently of the handling policy."""

        normalized = normalize_text(text)
        spans = self._detect_spans(normalized)
        return self._redact_spans(normalized, spans), self._safe_findings(spans)

    def evaluate(
        self,
        text: str,
        *,
        data_class: DataClass | str = DataClass.PUBLIC,
        confirmed: bool = False,
    ) -> DLPDecision:
        """Apply data classification and return the trust-boundary decision.

        Detector classification can only make a caller-provided class more
        restrictive.  A client cannot label a private key as ``public`` to
        bypass policy.  Unconfirmed ``confirm`` and all blocked/local-only
        outcomes intentionally return no egress payload.
        """

        normalized = normalize_text(text)
        spans = self._detect_spans(normalized)
        findings = self._safe_findings(spans)
        declared = _coerce_data_class(data_class)
        inferred = max(
            (item.data_class for item in findings),
            key=lambda item: _CLASS_RANK[item],
            default=DataClass.PUBLIC,
        )
        effective = max((declared, inferred), key=lambda item: _CLASS_RANK[item])
        action = self.policy.action_for(effective)
        if action is DLPAction.CONFIRM and confirmed:
            action = DLPAction.ALLOW

        output: str | None = None
        if action is DLPAction.ALLOW:
            output = normalized
        elif action is DLPAction.REDACT:
            output = self._redact_spans(normalized, spans)

        return DLPDecision(
            action=action,
            declared_data_class=declared,
            effective_data_class=effective,
            findings=findings,
            output_text=output,
            confirmed=confirmed,
        )

    inspect = evaluate


# Stateless convenience API for simple integration points.
_DEFAULT_SCANNER = DLPScanner()


def scan_text(text: str) -> tuple[DLPFinding, ...]:
    return _DEFAULT_SCANNER.scan(text)


def redact_text(text: str) -> tuple[str, tuple[DLPFinding, ...]]:
    return _DEFAULT_SCANNER.redact(text)


def evaluate_text(
    text: str,
    *,
    data_class: DataClass | str = DataClass.PUBLIC,
    confirmed: bool = False,
) -> DLPDecision:
    return _DEFAULT_SCANNER.evaluate(text, data_class=data_class, confirmed=confirmed)


__all__ = [
    "Action",
    "CustomDictionary",
    "DLPAction",
    "DLPDecision",
    "DLPFinding",
    "DLPPolicy",
    "DLPScanner",
    "DataClass",
    "DataClassification",
    "Decision",
    "FindingSeverity",
    "FindingType",
    "evaluate_text",
    "is_luhn_valid",
    "normalize_text",
    "redact_text",
    "scan_text",
]
