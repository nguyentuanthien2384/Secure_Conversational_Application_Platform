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
