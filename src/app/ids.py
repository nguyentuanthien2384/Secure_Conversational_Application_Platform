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

import hashlib
import html
import json
import re
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any
from urllib.parse import unquote_plus

from sqlalchemy import and_, case, delete, func, or_, select, text
from sqlalchemy.orm import Session

from src.app.db import utcnow
from src.app.models import AuditEvent, IntrusionDetection, IntrusionSource

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
    evidence_sha256: str
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
            # Only the digest is retained; raw request/header fragments may
            # contain credentials and never enter the in-memory IDS history.
            "evidence_sha256": self.evidence_sha256,
            "mitre_technique": self.mitre_technique,
            "detected_at": self.detected_at,
        }


def evidence_fingerprint(value: str) -> str:
    """Return a stable correlation value without retaining attacker input."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


# The HTTP middleware rejects larger request targets before scanning. Keep the
# same bound here for non-HTTP callers so decoding and regular-expression work
# never scales with an unbounded attacker-supplied string.
MAX_SCAN_TEXT_CHARS = 16_384
MAX_DECODE_PASSES = 3
_TEXT_ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))")
_XSS_IGNORED_CONTROLS = str.maketrans("", "", "\t\r\n")


def _decode_text_escape(match: re.Match[str]) -> str:
    return chr(int(match.group(1) or match.group(2), 16))


def _scan_candidates(text: str) -> list[str]:
    """Produce a fixed number of detection-only canonical representations.

    Never feed these values back into request handling: HTML/JSON/URL decoding
    is context dependent, and an IDS hit is evidence of a probe, not proof that
    the application would execute it. Repeated decoding stops at a fixed bound
    even for deliberately nested encodings.
    """
    candidates = [text]
    for _ in range(MAX_DECODE_PASSES):
        decoded = html.unescape(_TEXT_ESCAPE.sub(_decode_text_escape, unquote_plus(text)))
        if decoded == text:
            break
        if decoded not in candidates:
            candidates.append(decoded)
        text = decoded
    return candidates


def _sql_comment_view(text: str) -> str:
    """Replace SQL comments with spaces, preserving MySQL executable comments.

    Walk non-overlapping spans instead of an unbounded lazy regex: many open
    comment markers with no closing marker must not cause quadratic searching.
    This is a signature view, not a SQL parser or an input sanitizer.
    """
    parts: list[str] = []
    cursor = 0
    while True:
        start = text.find("/*", cursor)
        if start == -1:
            parts.append(text[cursor:])
            break
        end = text.find("*/", start + 2)
        if end == -1:
            parts.append(text[cursor:])
            break
        parts.append(text[cursor:start])
        if text.startswith("/*!", start):
            executable = text[start + 3 : end]
            # MySQL's optional version gate precedes the executable content.
            executable = re.sub(r"^\d{5,6}\s*", "", executable)
            parts.append(f" {executable} ")
        else:
            parts.append(" ")
        cursor = end + 2
    return "".join(parts)


def scan_text(text: str) -> list[tuple[str, str, str, str]]:
    """Inspect raw and bounded canonical views, retaining one hit per rule.

    Returns ``(rule_id, severity, description, matched_text)`` tuples. This only
    covers known patterns; deeply nested or novel obfuscation may still evade
    it. Oversized input is rejected rather than silently ignoring its tail.
    """
    if len(text) > MAX_SCAN_TEXT_CHARS:
        raise ValueError("IDS scan input exceeds the request-target limit.")
    if not text:
        return []
    candidates = _scan_candidates(text)
    hits: list[tuple[str, str, str, str]] = []
    sql_candidates = [_sql_comment_view(candidate) for candidate in candidates]
    xss_candidates = [candidate.translate(_XSS_IGNORED_CONTROLS) for candidate in candidates]
    for rule_id, severity, pattern, description in SIGNATURES:
        views = candidates
        if rule_id.startswith("SQLI-"):
            views = candidates + sql_candidates
        elif rule_id.startswith("XSS-"):
            views = candidates + xss_candidates
        for candidate in dict.fromkeys(views):
            match = pattern.search(candidate)
            if match:
                hits.append((rule_id, severity, description, match.group(0)[:120]))
                break
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

    Kept for isolated unit tests. Application runtimes use
    ``PersistentIntrusionState`` so workers share detection history and bans.
    """

    def __init__(
        self,
        *,
        block_threshold: int = 5,
        block_seconds: int = 900,
        history: int = 500,
        max_sources: int = 10_000,
    ) -> None:
        if min(block_threshold, block_seconds, history, max_sources) <= 0:
            raise ValueError("IDS thresholds, retention and source capacity must be positive.")
        self.block_threshold = block_threshold
        self.block_seconds = block_seconds
        self.max_sources = max_sources
        self._lock = Lock()
        self._detections: deque[Detection] = deque(maxlen=history)
        self._scores: OrderedDict[str, deque[float]] = OrderedDict()
        self._blocked: dict[str, float] = {}
        self._next_cleanup = 0.0

    _SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1}

    def _expire_source(self, source_ip: str, now: float) -> None:
        expiry = self._blocked.get(source_ip)
        if expiry is not None and expiry <= now:
            self._blocked.pop(source_ip, None)
            # A served ban starts a fresh observation window. Otherwise a hit
            # immediately after expiry can reuse the old score and re-ban it.
            self._scores.pop(source_ip, None)

    def _cleanup(self, now: float, *, force: bool = False) -> None:
        """Remove idle sources even when their addresses never return."""
        if not force and now < self._next_cleanup:
            return
        cutoff = now - self.block_seconds
        for source_ip in list(self._scores):
            self._expire_source(source_ip, now)
            bucket = self._scores.get(source_ip)
            if bucket is not None and source_ip not in self._blocked:
                while bucket and bucket[0] <= cutoff:
                    bucket.popleft()
                if not bucket:
                    self._scores.pop(source_ip, None)
        self._next_cleanup = now + min(60, self.block_seconds)

    def record(self, detection: Detection) -> bool:
        """Store a detection; return True if this pushed the source over the block threshold."""
        weight = self._SEVERITY_WEIGHT.get(detection.severity, 1)
        now = time.monotonic()
        cutoff = now - self.block_seconds
        with self._lock:
            self._detections.append(detection)
            self._cleanup(now)
            self._expire_source(detection.source_ip, now)
            if detection.source_ip not in self._scores:
                if len(self._scores) >= self.max_sources:
                    self._cleanup(now, force=True)
                if len(self._scores) >= self.max_sources:
                    # Preserve active bans when capacity is reached. Reclaim
                    # the oldest unblocked source; if every slot is blocked,
                    # only the bounded detection history records this source.
                    oldest = next(
                        (ip for ip in self._scores if ip not in self._blocked), None
                    )
                    if oldest is None:
                        return False
                    self._scores.pop(oldest)
                self._scores[detection.source_ip] = deque(maxlen=self.block_threshold)
            bucket = self._scores[detection.source_ip]
            self._scores.move_to_end(detection.source_ip)
            while bucket and bucket[0] <= cutoff:
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
            self._cleanup(now)
            self._expire_source(source_ip, now)
            expiry = self._blocked.get(source_ip)
            if expiry is None:
                return False, 0
            return True, max(1, int(expiry - now))

    def unblock(self, source_ip: str, *, db: Session | None = None) -> bool:
        with self._lock:
            self._scores.pop(source_ip, None)
            return self._blocked.pop(source_ip, None) is not None

    def blocked_sources(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        with self._lock:
            self._cleanup(now, force=True)
            return [
                {"source_ip": ip, "seconds_remaining": max(0, int(expiry - now))}
                for ip, expiry in sorted(self._blocked.items())
                if expiry > now
            ]

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._detections)[-limit:]
        return [item.as_dict() for item in reversed(items)]


class PersistentIntrusionState:
    """Database-backed IDS state shared across processes and application restarts.

    Mutation transactions serialize on a dedicated PostgreSQL advisory lock or
    SQLite's writer lock. This covers the score, one-time block transition,
    unblock, and capacity pruning together; Python locks cannot protect separate
    workers. Read-only checks use expiry predicates and never take a writer lock.
    The bounded operational history is separate from the append-only audit log.
    All PostgreSQL workers use the database clock for score windows and bans.
    """

    _ADVISORY_LOCK_ID = 0x53434150494453  # SCAPIDS; distinct from audit/maintenance locks.
    _SEVERITY_WEIGHT = IntrusionState._SEVERITY_WEIGHT

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        block_threshold: int = 5,
        block_seconds: int = 900,
        history: int = 500,
        max_sources: int = 10_000,
    ) -> None:
        if min(block_threshold, block_seconds, history, max_sources) <= 0:
            raise ValueError("IDS thresholds, retention and source capacity must be positive.")
        self._session_factory = session_factory
        self.block_threshold = block_threshold
        self.block_seconds = block_seconds
        self.history = history
        self.max_sources = max_sources

    @staticmethod
    def _utc(value: datetime) -> datetime:
        # SQLite's DateTime adapter returns a naive UTC value.
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

    def _now(self, db: Session) -> datetime:
        if db.get_bind().dialect.name == "postgresql":
            return self._utc(db.scalar(select(func.clock_timestamp())))
        return self._utc(utcnow())

    def _lock_writer(self, db: Session, *, existing_transaction: bool = False) -> None:
        dialect = db.get_bind().dialect.name
        if dialect == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": self._ADVISORY_LOCK_ID})
        elif dialect == "sqlite":
            if not existing_transaction:
                # Acquire the writer reservation before reading scores; a
                # deferred read followed by UPDATE can race or fail to upgrade.
                db.execute(text("BEGIN IMMEDIATE"))
            elif not db.connection().connection.driver_connection.in_transaction:
                raise RuntimeError("Shared IDS mutation requires an active SQLite write transaction.")
        else:
            raise RuntimeError("Persistent IDS state supports SQLite and PostgreSQL only.")

    def _prune_sources(self, db: Session, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.block_seconds)
        db.execute(delete(IntrusionSource).where(or_(
            IntrusionSource.blocked_until <= now,
            and_(IntrusionSource.blocked_until.is_(None), IntrusionSource.last_seen_at <= cutoff),
        )))

    def _retain_detection(self, db: Session, detection: Detection) -> None:
        # Detection.as_dict is an explicit allowlist. Request bodies, raw query
        # strings, and header evidence are never persisted here. The request
        # scanner supplies its already-sanitized path and evidence digest.
        db.add(IntrusionDetection(payload_json=json.dumps(detection.as_dict(), ensure_ascii=False)))
        db.flush()
        oldest_retained = db.scalar(
            select(IntrusionDetection.id).order_by(IntrusionDetection.id.desc())
            .offset(self.history - 1).limit(1)
        )
        if oldest_retained is not None:
            db.execute(delete(IntrusionDetection).where(IntrusionDetection.id < oldest_retained))

    def record(self, detection: Detection) -> bool:
        """Persist one sanitized hit, atomically returning the new-ban transition."""
        with self._session_factory() as db, db.begin():
            self._lock_writer(db)
            now = self._now(db)
            self._prune_sources(db, now)
            self._retain_detection(db, detection)
            source = db.get(IntrusionSource, detection.source_ip)
            if source is None:
                if db.scalar(select(func.count()).select_from(IntrusionSource)) >= self.max_sources:
                    oldest = db.scalar(
                        select(IntrusionSource).where(IntrusionSource.blocked_until.is_(None))
                        .order_by(IntrusionSource.last_seen_at, IntrusionSource.source_ip).limit(1)
                    )
                    # Retain active bans under a source-rotation flood. When
                    # all slots are blocked, only detection history is updated.
                    if oldest is None:
                        return False
                    db.delete(oldest)
                source = IntrusionSource(source_ip=detection.source_ip, score_times_json="[]", last_seen_at=now)
                db.add(source)
            cutoff = (now - timedelta(seconds=self.block_seconds)).timestamp()
            scores = [stamp for stamp in json.loads(source.score_times_json) if stamp > cutoff]
            scores.extend([now.timestamp()] * self._SEVERITY_WEIGHT.get(detection.severity, 1))
            scores = scores[-self.block_threshold:]
            source.score_times_json = json.dumps(scores)
            source.last_seen_at = now
            if len(scores) >= self.block_threshold and source.blocked_until is None:
                source.blocked_until = now + timedelta(seconds=self.block_seconds)
                return True
        return False

    def is_blocked(self, source_ip: str) -> tuple[bool, int]:
        with self._session_factory() as db:
            now = self._now(db)
            expiry = db.scalar(select(IntrusionSource.blocked_until).where(
                IntrusionSource.source_ip == source_ip, IntrusionSource.blocked_until > now,
            ))
            if expiry is None:
                return False, 0
            return True, max(1, int((self._utc(expiry) - now).total_seconds()))

    def _unblock(self, db: Session, source_ip: str, *, existing_transaction: bool) -> bool:
        self._lock_writer(db, existing_transaction=existing_transaction)
        now = self._now(db)
        source = db.get(IntrusionSource, source_ip)
        if source is None:
            return False
        active = source.blocked_until is not None and self._utc(source.blocked_until) > now
        db.delete(source)
        return active

    def unblock(self, source_ip: str, *, db: Session | None = None) -> bool:
        """Clear a score/ban, optionally in the caller's admin/audit transaction.

        A supplied SQLite session must already hold its account-policy writer
        reservation. No commit is issued for a supplied session, so an audit
        failure rolls back the unblock too. PostgreSQL takes the IDS lock after
        the caller's account-policy lock and holds it until that transaction ends.
        """
        if db is not None:
            return self._unblock(db, source_ip, existing_transaction=True)
        with self._session_factory() as session, session.begin():
            return self._unblock(session, source_ip, existing_transaction=False)

    def blocked_sources(self) -> list[dict[str, Any]]:
        with self._session_factory() as db:
            now = self._now(db)
            return [
                {"source_ip": ip, "seconds_remaining": max(1, int((self._utc(expiry) - now).total_seconds()))}
                for ip, expiry in db.execute(
                    select(IntrusionSource.source_ip, IntrusionSource.blocked_until)
                    .where(IntrusionSource.blocked_until > now).order_by(IntrusionSource.source_ip)
                )
            ]

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        with self._session_factory() as db:
            return [json.loads(payload) for payload in db.scalars(
                select(IntrusionDetection.payload_json).order_by(IntrusionDetection.id.desc())
                .limit(min(limit, self.history))
            )]


# ─────────────────────────── anomaly engine ───────────────────────────


@dataclass(frozen=True)
class Anomaly:
    code: str
    severity: str
    message: str
    count: int
    window_minutes: int
    subject: str | None = None
    mitre_technique: str | None = None
    source_count: int | None = None
    evidence_event_id: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "count": self.count,
            "window_minutes": self.window_minutes,
            "subject": self.subject,
            "mitre_technique": self.mitre_technique,
            "source_count": self.source_count,
            "evidence_event_id": self.evidence_event_id,
        }


# Correlation stays in SQL: no request bodies, credentials, or unbounded list of
# raw events is loaded into application memory. The administrator can narrow
# the window to investigate additional accounts in a very large incident.
MAX_CORRELATION_FINDINGS = 100


def _authentication_correlations(
    db: Session,
    *,
    cutoff: datetime,
    now: datetime,
    window_minutes: int,
    failure_threshold: int,
    distributed_source_threshold: int,
) -> list[Anomaly]:
    """Observe attack-shaped authentication sequences without blocking users.

    Account/source correlation follows Wazuh's same/different-field approach
    and Microsoft Sentinel's distributed-password detection. Neither changing
    IPs nor a recovered password proves compromise; findings need investigation.
    Only completed login or MFA verification events count as success.
    """
    valid_source = AuditEvent.ip_address.not_in(("", "unknown"))
    distributed = db.execute(
        select(
            AuditEvent.actor_id,
            func.count(AuditEvent.id).label("failures"),
            func.count(func.distinct(AuditEvent.ip_address)).label("sources"),
            func.max(AuditEvent.id).label("evidence_id"),
        )
        .where(
            AuditEvent.event_type == "auth.login",
            AuditEvent.outcome.in_(("failure", "blocked", "denied")),
            AuditEvent.actor_id.is_not(None),
            AuditEvent.actor_id != "",
            valid_source,
            AuditEvent.created_at >= cutoff,
            AuditEvent.created_at <= now,
        )
        .group_by(AuditEvent.actor_id)
        .having(
            func.count(AuditEvent.id) >= failure_threshold,
            func.count(func.distinct(AuditEvent.ip_address)) >= distributed_source_threshold,
        )
        .order_by(func.count(AuditEvent.id).desc(), AuditEvent.actor_id)
        .limit(MAX_CORRELATION_FINDINGS)
    ).all()
    findings = [
        Anomaly(
            "IDS-DISTRIBUTED-BRUTEFORCE",
            "high",
            f"Tài khoản {actor} có {failures} lần đăng nhập thất bại từ {sources} nguồn "
            f"trong {window_minutes} phút; cần điều tra dấu hiệu dò mật khẩu phân tán.",
            failures,
            window_minutes,
            subject=actor,
            mitre_technique="T1110.001",
            source_count=sources,
            evidence_event_id=evidence_id,
        )
        for actor, failures, sources, evidence_id in distributed
    ]

    # A successful authentication ends its preceding failure sequence. Window
    # rows exclude the current row so the success remains in that sequence;
    # the next event starts a new one. Timestamp then id gives deterministic
    # chronology, including equal database timestamps and backfilled events.
    successful = case((AuditEvent.outcome == "success", 1), else_=0)
    ordered = (
        select(
            AuditEvent.id,
            AuditEvent.actor_id,
            AuditEvent.outcome,
            AuditEvent.ip_address,
            AuditEvent.created_at,
            func.coalesce(
                func.sum(successful).over(
                    partition_by=AuditEvent.actor_id,
                    order_by=(AuditEvent.created_at, AuditEvent.id),
                    rows=(None, -1),
                ),
                0,
            ).label("episode"),
        )
        .where(
            AuditEvent.event_type.in_(("auth.login", "auth.mfa.verify")),
            AuditEvent.outcome.in_(("success", "failure", "blocked", "denied")),
            AuditEvent.actor_id.is_not(None),
            AuditEvent.actor_id != "",
            AuditEvent.created_at >= cutoff,
            AuditEvent.created_at <= now,
        )
        .subquery()
    )
    failure_count = func.sum(case((ordered.c.outcome != "success", 1), else_=0))
    success_id = func.max(case((ordered.c.outcome == "success", ordered.c.id)))
    success_at = func.max(case((ordered.c.outcome == "success", ordered.c.created_at)))
    episodes = (
        select(
            ordered.c.actor_id,
            failure_count.label("failures"),
            func.count(func.distinct(case(
                (
                    (ordered.c.outcome != "success")
                    & ordered.c.ip_address.not_in(("", "unknown")),
                    ordered.c.ip_address,
                ),
            ))).label("sources"),
            success_id.label("success_id"),
            success_at.label("success_at"),
        )
        .group_by(ordered.c.actor_id, ordered.c.episode)
        .having(failure_count >= failure_threshold, success_id.is_not(None))
        .subquery()
    )
    ranked = select(
        episodes,
        func.row_number().over(
            partition_by=episodes.c.actor_id,
            order_by=(episodes.c.success_at.desc(), episodes.c.success_id.desc()),
        ).label("rank"),
    ).subquery()
    sequences = db.execute(
        select(ranked.c.actor_id, ranked.c.failures, ranked.c.sources, ranked.c.success_id)
        .where(ranked.c.rank == 1)
        .order_by(ranked.c.success_at.desc(), ranked.c.success_id.desc(), ranked.c.actor_id)
        .limit(MAX_CORRELATION_FINDINGS)
    ).all()
    findings.extend(
        Anomaly(
            "IDS-AUTH-SUCCESS-AFTER-FAILURES",
            "high",
            f"Tài khoản {actor} đã hoàn tất đăng nhập sau {failures} lần xác thực thất bại "
            f"liên tiếp trong {window_minutes} phút; cần xác minh với chủ tài khoản.",
            failures,
            window_minutes,
            subject=actor,
            mitre_technique="T1110",
            source_count=sources,
            evidence_event_id=event_id,
        )
        for actor, failures, sources, event_id in sequences
    )
    return findings


def detect_anomalies(
    db: Session,
    *,
    window_minutes: int = 60,
    brute_force_threshold: int = 5,
    spray_account_threshold: int = 3,
    idor_threshold: int = 5,
    distributed_source_threshold: int = 3,
) -> list[Anomaly]:
    """Correlate recent audit events into attack-shaped findings.

    These rules are deliberately about *shape*, not volume: many failures from
    one IP against many accounts is password spraying, whereas many failures
    against one account is classic brute force. The distinction changes the
    response, which is exactly what an IDS is for.
    """
    if not 1 <= window_minutes <= 1_440:
        raise ValueError("IDS correlation window must be between 1 and 1440 minutes.")
    if min(brute_force_threshold, spray_account_threshold, idor_threshold) < 1:
        raise ValueError("IDS correlation thresholds must be positive.")
    if distributed_source_threshold < 2:
        raise ValueError("Distributed authentication correlation requires at least two sources.")
    now = utcnow()
    cutoff = now - timedelta(minutes=window_minutes)
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

    anomalies.extend(_authentication_correlations(
        db,
        cutoff=cutoff,
        now=now,
        window_minutes=window_minutes,
        failure_threshold=brute_force_threshold,
        distributed_source_threshold=distributed_source_threshold,
    ))
    return anomalies
