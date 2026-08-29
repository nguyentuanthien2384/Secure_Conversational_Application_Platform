"""Application-layer IDS / IPS (Bài 7 §7.3 IDS, Bài 2 §2.5, Bài 3.2 §WAF).

A network IDS sees packets; it cannot tell an authenticated IDOR probe from a
normal API call because both are valid TLS traffic to the same endpoint. This
module is the application-layer counterpart: it inspects requests *and* the
project's own audit stream, raises signature- and anomaly-based alerts, and can
promote detection to prevention by blocking an offending source address.

Two engines, mirroring the taxonomy in the slides:

1. ``signature`` — pattern matching on the raw request (SQLi / XSS / path
   traversal / scanner user-agents). Fast, low false-negative on known tooling,
   blind to novel attacks.
2. ``anomaly`` — statistical rules over recent audit events (credential
   stuffing across many accounts, brute force on one account, bursts of
   authorization denials that indicate IDOR enumeration).

Honest scope for the report: this is *defence in depth*, not the primary
control. SQL injection is already structurally impossible here because every
query goes through SQLAlchemy's parameter binding; the signature engine exists
to detect and log attempts, and must never be presented as the reason the app
is safe. Pattern matching on request text is trivially bypassable.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from threading import Lock
from typing import Any
from urllib.parse import unquote_plus

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.app.db import utcnow
from src.app.models import AuditEvent

# ─────────────────────────── signature engine ───────────────────────────

# Each rule: (id, severity, compiled pattern, human description)
SIGNATURES: tuple[tuple[str, str, re.Pattern[str], str], ...] = (
    (
        "SQLI-001",
        "high",
        re.compile(
            r"(?i)(\bunion\b[\s\S]{0,40}\bselect\b|\bselect\b[\s\S]{0,40}\bfrom\b\s+information_schema)"
        ),
        "Chuỗi UNION SELECT / truy vấn information_schema (SQL Injection)",
    ),
    (
        "SQLI-002",
        "high",
        re.compile(r"(?i)(\bor\b|\band\b)\s*['\"]?\s*\d+\s*=\s*\d+|'\s*(or|and)\s*'1'\s*=\s*'1"),
        "Biểu thức tautology kiểu ' OR 1=1 (SQL Injection)",
    ),
    (
        "SQLI-003",
        "medium",
        re.compile(r"(?i)(\bsleep\s*\(|\bbenchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay)"),
        "Hàm gây trễ dùng cho blind/time-based SQL Injection",
    ),
    (
        "XSS-001",
        "high",
        re.compile(r"(?i)<\s*script\b|javascript\s*:|on(error|load|mouseover|focus)\s*="),
        "Payload kịch bản phía trình duyệt (Cross-Site Scripting)",
    ),
    (
        "XSS-002",
        "medium",
        re.compile(
            r"(?i)<\s*(iframe|svg|img|object|embed)\b[^>]*(on\w+|src\s*=\s*['\"]?\s*javascript)"
        ),
        "Thẻ HTML mang handler sự kiện (XSS qua HTML injection)",
    ),
    (
        "TRAV-001",
        "high",
        re.compile(r"(\.\./|\.\.\\){2,}|/etc/(passwd|shadow)\b|\bboot\.ini\b"),
        "Path traversal / truy cập file hệ thống",
    ),
    (
        "CMDI-001",
        "high",
        re.compile(
            r"(?i)[;|`]\s*(cat|wget|curl|nc|bash|sh|powershell|whoami|id)(?=[\s;|&'\"`)]|$)|\$\([^)]+\)"
        ),
        "Chuỗi chèn lệnh hệ điều hành (Command Injection)",
    ),
    (
        "SSTI-001",
        "medium",
        re.compile(r"\{\{\s*[\w.\[\]']+\s*\}\}|\{%\s*\w+"),
        "Cú pháp template có thể dẫn tới Server-Side Template Injection",
    ),
    (
        "LOGI-001",
        "medium",
        re.compile(r"\$\{\s*jndi\s*:", re.IGNORECASE),
        "Chuỗi JNDI kiểu Log4Shell",
    ),
    (
        "NOSQ-001",
        "medium",
        re.compile(r"(?i)\$(ne|gt|lt|where|regex)\b\s*:"),
        "Toán tử NoSQL injection",
    ),
)

SCANNER_AGENTS = re.compile(
    r"(?i)\b(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|feroxbuster|"
    r"wpscan|zgrab|zaproxy|owasp\s*zap|burp(suite)?|hydra|metasploit|commix|xsstrike)\b"
)

# Paths that only exist on other stacks: requesting them is reconnaissance.
DECOY_PATHS = re.compile(
    r"(?i)^/(wp-admin|wp-login\.php|phpmyadmin|\.env|\.git/|admin\.php|xmlrpc\.php|"
    r"config\.php|\.aws/|\.ssh/|actuator|solr/|cgi-bin/)"
)

# The reference project is organised around MITRE ATT&CK techniques.  Keep the
# mapping close to the controls instead of hiding it in a dashboard: this makes
# every SIEM event useful to an analyst and gives the project a testable,
# honest coverage boundary.  These request signatures are all evidence of
# exploitation attempts against a public-facing application (T1190).
_T1190_RULES = frozenset(
    {
        "SQLI-001",
        "SQLI-002",
        "SQLI-003",
        "XSS-001",
        "XSS-002",
        "TRAV-001",
        "CMDI-001",
        "SSTI-001",
        "LOGI-001",
        "NOSQ-001",
    }
)


def mitre_technique_for_rule(rule_id: str) -> str | None:
    """Return the ATT&CK technique represented by an IDS rule, when scoped.

    Scanner and decoy-path rules intentionally return ``None``.  They are
    reconnaissance signals, but this application does not claim that a
    user-agent string alone proves a particular ATT&CK technique.
    """
    return "T1190" if rule_id in _T1190_RULES else None


@dataclass
class Detection:
    """One IDS hit."""

    rule_id: str
    severity: str
    engine: str
    description: str
    source_ip: str
    path: str
    method: str
    evidence: str
    mitre_technique: str | None = None
    detected_at: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "engine": self.engine,
            "description": self.description,
            "source_ip": self.source_ip,
            "path": self.path,
            "method": self.method,
            "evidence": self.evidence,
            "mitre_technique": self.mitre_technique,
            "detected_at": self.detected_at,
        }


def scan_text(text: str) -> list[tuple[str, str, str, str]]:
    """Run every signature over one decoded string.

    Returns ``(rule_id, severity, description, matched_text)`` tuples. The URL is
    decoded twice because attackers routinely double-encode to slip past naive
    filters (``%252e%252e%252f``).
    """
    if not text:
        return []
    candidates = {text, unquote_plus(text)}
    candidates.add(unquote_plus(unquote_plus(text)))
    hits: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for candidate in candidates:
        for rule_id, severity, pattern, description in SIGNATURES:
            if rule_id in seen:
                continue
            match = pattern.search(candidate)
            if match:
                seen.add(rule_id)
                hits.append((rule_id, severity, description, match.group(0)[:120]))
    return hits


# ─────────────────── Purple Team safe verification ───────────────────

# These are *in-process test strings*, not HTTP requests and not executable
# exploits.  They exercise the same signature engine that middleware uses,
# giving an admin a repeatable Hit/Miss check without touching a target,
# database, shell, or external network.
SAFE_VERIFICATION_SCENARIOS: tuple[tuple[str, str, str, str], ...] = (
    ("SQL injection", "T1190", "id=1%20UNION%20SELECT%20username,password", "SQLI-001"),
    ("Cross-site scripting", "T1190", "q=%3Cscript%3Ealert(1)%3C/script%3E", "XSS-001"),
    ("Path traversal", "T1190", "file=%252e%252e%252f%252e%252e%252fetc%252fpasswd", "TRAV-001"),
    ("Command injection", "T1190", "host=127.0.0.1%3Bwhoami", "CMDI-001"),
)


def run_safe_detection_verification() -> dict[str, Any]:
    """Measure deterministic IDS rule coverage for the supported ATT&CK scope.

    The report deliberately distinguishes a rule-engine check from a full
    penetration test or SIEM-pipeline test.  That prevents a 100% result here
    from being misrepresented as proof that the whole deployment is secure.
    """
    scenarios: list[dict[str, Any]] = []
    for name, technique, sample, expected_rule in SAFE_VERIFICATION_SCENARIOS:
        observed_rules = [rule_id for rule_id, *_rest in scan_text(sample)]
        scenarios.append(
            {
                "name": name,
                "mitre_technique": technique,
                "expected_rule": expected_rule,
                "observed_rules": observed_rules,
                "result": "hit" if expected_rule in observed_rules else "miss",
            }
        )
    detected = sum(item["result"] == "hit" for item in scenarios)
    total = len(scenarios)
    return {
        "verification_type": "safe_in_process_signature_check",
        "scope": "Application IDS signature rules for MITRE ATT&CK T1190.",
        "not_covered": (
            "This does not execute attacks, test operating-system telemetry, or verify an "
            "external SIEM ingestion pipeline."
        ),
        "total_scenarios": total,
        "detected_scenarios": detected,
        "missed_scenarios": total - detected,
        "detection_rate": round((detected / total) * 100, 2) if total else 0.0,
        "scenarios": scenarios,
    }


# ─────────────────────────── prevention state ───────────────────────────


class IntrusionState:
    """In-memory detection log + dynamic blocklist (the 'P' in IPS).

    In-memory is the right scope for a single-instance teaching deployment. A
    real multi-node deployment must share this state — Redis, or better, push
    the decision to the edge (fail2ban / Caddy / cloud WAF) so blocked traffic
    never reaches the application at all.
    """

    def __init__(
        self, *, block_threshold: int = 5, block_seconds: int = 900, history: int = 500
    ) -> None:
        self.block_threshold = block_threshold
        self.block_seconds = block_seconds
        self._lock = Lock()
        self._detections: deque[Detection] = deque(maxlen=history)
        self._scores: dict[str, deque[float]] = defaultdict(deque)
        self._blocked: dict[str, float] = {}

    _SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1}

    def record(self, detection: Detection) -> bool:
        """Store a detection; return True if this pushed the source over the block threshold."""
        weight = self._SEVERITY_WEIGHT.get(detection.severity, 1)
        now = time.monotonic()
        cutoff = now - self.block_seconds
        with self._lock:
            self._detections.append(detection)
            bucket = self._scores[detection.source_ip]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            for _ in range(weight):
                bucket.append(now)
            if len(bucket) >= self.block_threshold and detection.source_ip not in self._blocked:
                self._blocked[detection.source_ip] = now + self.block_seconds
                return True
        return False

    def is_blocked(self, source_ip: str) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            expiry = self._blocked.get(source_ip)
            if expiry is None:
                return False, 0
            if expiry <= now:
                del self._blocked[source_ip]
                return False, 0
            return True, max(1, int(expiry - now))

    def unblock(self, source_ip: str) -> bool:
        with self._lock:
            return self._blocked.pop(source_ip, None) is not None

    def blocked_sources(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        with self._lock:
            return [
                {"source_ip": ip, "seconds_remaining": max(0, int(expiry - now))}
                for ip, expiry in sorted(self._blocked.items())
                if expiry > now
            ]

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._detections)[-limit:]
        return [item.as_dict() for item in reversed(items)]


# ─────────────────────────── anomaly engine ───────────────────────────


@dataclass(frozen=True)
class Anomaly:
    code: str
    severity: str
    message: str
    count: int
    window_minutes: int
    subject: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "count": self.count,
            "window_minutes": self.window_minutes,
            "subject": self.subject,
        }


def detect_anomalies(
    db: Session,
    *,
    window_minutes: int = 60,
    brute_force_threshold: int = 5,
    spray_account_threshold: int = 3,
    idor_threshold: int = 5,
) -> list[Anomaly]:
    """Correlate recent audit events into attack-shaped findings.

    These rules are deliberately about *shape*, not volume: many failures from
    one IP against many accounts is password spraying, whereas many failures
    against one account is classic brute force. The distinction changes the
    response, which is exactly what an IDS is for.
    """
    cutoff = utcnow() - timedelta(minutes=window_minutes)
    anomalies: list[Anomaly] = []

    # 1. Brute force: repeated failed logins from a single source address.
    rows = db.execute(
        select(AuditEvent.ip_address, func.count(AuditEvent.id))
        .where(
            AuditEvent.event_type == "auth.login",
            AuditEvent.outcome != "success",
            AuditEvent.created_at >= cutoff,
        )
        .group_by(AuditEvent.ip_address)
    ).all()
    for ip, count in rows:
        if count >= brute_force_threshold:
            anomalies.append(
                Anomaly(
                    "IDS-BRUTEFORCE",
                    "high" if count >= brute_force_threshold * 2 else "medium",
                    f"{count} lần đăng nhập thất bại từ {ip} trong {window_minutes} phút.",
                    count,
                    window_minutes,
                    subject=ip,
                )
            )

    # 2. Password spraying / credential stuffing: one source, many distinct victims.
    spray = db.execute(
        select(AuditEvent.ip_address, func.count(func.distinct(AuditEvent.actor_id)))
        .where(
            AuditEvent.event_type == "auth.login",
            AuditEvent.outcome != "success",
            AuditEvent.actor_id.is_not(None),
            AuditEvent.created_at >= cutoff,
        )
        .group_by(AuditEvent.ip_address)
    ).all()
    for ip, distinct_accounts in spray:
        if distinct_accounts >= spray_account_threshold:
            anomalies.append(
                Anomaly(
                    "IDS-CREDENTIAL-SPRAY",
                    "high",
                    f"{ip} thất bại đăng nhập trên {distinct_accounts} tài khoản khác nhau "
                    f"trong {window_minutes} phút (dấu hiệu password spraying).",
                    distinct_accounts,
                    window_minutes,
                    subject=ip,
                )
            )

    # 3. IDOR / BOLA enumeration: bursts of authorization denials per actor.
    idor = db.execute(
        select(AuditEvent.actor_id, func.count(AuditEvent.id))
        .where(
            AuditEvent.event_type == "authorization.denied",
            AuditEvent.created_at >= cutoff,
        )
        .group_by(AuditEvent.actor_id)
    ).all()
    for actor_id, count in idor:
        if count >= idor_threshold:
            anomalies.append(
                Anomaly(
                    "IDS-IDOR-PROBE",
                    "high",
                    f"Tài khoản {actor_id} bị từ chối truy cập {count} lần "
                    f"trong {window_minutes} phút (dò tài nguyên của người khác).",
                    count,
                    window_minutes,
                    subject=actor_id,
                )
            )

    # 4. MFA hammering: repeated second-factor failures.
    mfa_failures = (
        db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.event_type == "auth.mfa.verify",
                AuditEvent.outcome != "success",
                AuditEvent.created_at >= cutoff,
            )
        )
        or 0
    )
    if mfa_failures >= brute_force_threshold:
        anomalies.append(
            Anomaly(
                "IDS-MFA-BRUTEFORCE",
                "high",
                f"{mfa_failures} lần nhập sai mã xác thực hai lớp trong {window_minutes} phút.",
                mfa_failures,
                window_minutes,
            )
        )

    # 5. Signature hits recorded by the request scanner.
    waf_hits = db.execute(
        select(AuditEvent.ip_address, func.count(AuditEvent.id))
        .where(AuditEvent.event_type == "ids.signature", AuditEvent.created_at >= cutoff)
        .group_by(AuditEvent.ip_address)
    ).all()
    for ip, count in waf_hits:
        anomalies.append(
            Anomaly(
                "IDS-ATTACK-PATTERN",
                "high",
                f"{count} request chứa mẫu tấn công đã biết từ {ip} trong {window_minutes} phút.",
                count,
                window_minutes,
                subject=ip,
            )
        )

    return anomalies
