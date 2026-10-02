"""Outbound security email: verification codes, password resets and alerts.

Messages are handed to a small background pool so the HTTP response time does
not depend on SMTP latency. That matters for password-reset requests, whose
response must look identical whether or not the account exists.

Transports:

* ``smtp``   — production; TLS is mandatory (STARTTLS or implicit TLS) and the
  server certificate is verified.
* ``outbox`` — development/demo; each message becomes an ``.eml`` file in a
  local directory, so the classroom demo needs no mail server.
* ``disabled`` — no email features; endpoints that need email answer 503.

Log lines carry only the template name and a delivery id, never addresses,
codes or bodies.
"""

from __future__ import annotations

import logging
import re
import secrets
import smtplib
import ssl
import threading
from concurrent.futures import Future, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, parseaddr
from pathlib import Path
from typing import Protocol

logger = logging.getLogger("secure_chat.mail")

MAIL_BACKENDS = ("disabled", "outbox", "smtp")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


class MailUnavailable(RuntimeError):
    """Email delivery is not configured for this deployment."""


def normalize_email(value: str) -> str | None:
    """Return a canonical address (lower-cased) or ``None`` when it is not usable.

    Deliberately strict: ASCII local part and dotted domain, no display names,
    no quoted strings, no header-breaking characters.
    """
    candidate = (value or "").strip()
    if len(candidate) > 254 or any(ch in candidate for ch in "\r\n\x00<>,;\" "):
        return None
    if not _EMAIL_RE.fullmatch(candidate):
        return None
    local, _, domain = candidate.rpartition("@")
    if domain.startswith("-") or ".." in candidate or local.startswith(".") or local.endswith("."):
        return None
    return candidate.lower()


def mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    shown = local[:2] if len(local) > 2 else local[:1]
    return f"{shown}{'•' * 3}@{domain}"


class MailTransport(Protocol):
    def send(self, message: EmailMessage) -> None: ...


class OutboxTransport:
    """Write each message to ``<directory>/<timestamp>-<id>.eml`` (development only)."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    def send(self, message: EmailMessage) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        path = self.directory / f"{stamp}-{secrets.token_hex(4)}.eml"
        path.write_bytes(bytes(message))


class SmtpTransport:
    """Deliver over SMTP with certificate-verified TLS; plaintext is never used."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        username: str = "",
        password: str = "",
        security: str = "starttls",
        timeout: float = 15.0,
    ) -> None:
        if security not in ("starttls", "ssl"):
            raise ValueError("SMTP_SECURITY phải là starttls hoặc ssl.")
        self.host, self.port = host, port
        self.username, self.password = username, password
        self.security, self.timeout = security, timeout

    def send(self, message: EmailMessage) -> None:
        context = ssl.create_default_context()
        if self.security == "ssl":
            client: smtplib.SMTP = smtplib.SMTP_SSL(
                self.host, self.port, timeout=self.timeout, context=context
            )
        else:
            client = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
        with client:
            if self.security == "starttls":
                client.starttls(context=context)
            if self.username:
                client.login(self.username, self.password)
            client.send_message(message)


class Mailer:
    """Build plain-text security messages and deliver them off the request path."""

    def __init__(
        self,
        transport: MailTransport | None,
        sender: str,
        *,
        app_name: str = "SCAP",
        background: bool = True,
    ) -> None:
        name, address = parseaddr(sender)
        if normalize_email(address) is None:
            raise ValueError("MAIL_FROM phải là một địa chỉ email hợp lệ.")
        self.transport = transport
        self.sender = formataddr((name or app_name, address))
        self.app_name = app_name
        self.background = background
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scap-mail")
        self._pending: set[Future] = set()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.transport is not None

    def send(self, to: str, subject: str, body: str, *, template: str) -> None:
        if self.transport is None:
            raise MailUnavailable("Email delivery is not configured.")
        message = EmailMessage()
        message["From"] = self.sender
        message["To"] = to
        message["Subject"] = f"[{self.app_name}] {subject}"
        message["Message-ID"] = make_msgid(domain=self.sender.rpartition("@")[2].rstrip(">"))
        message["Auto-Submitted"] = "auto-generated"
        message.set_content(body)
        delivery_id = secrets.token_hex(6)
        if not self.background:
            self._deliver(message, template, delivery_id)
            return
        future = self._executor.submit(self._deliver, message, template, delivery_id)
        with self._lock:
            self._pending.add(future)
        future.add_done_callback(self._forget)

    def _forget(self, future: Future) -> None:
        with self._lock:
            self._pending.discard(future)

    def _deliver(self, message: EmailMessage, template: str, delivery_id: str) -> None:
        try:
            self.transport.send(message)  # type: ignore[union-attr]
            logger.info("Security email delivered (template=%s, id=%s).", template, delivery_id)
        except Exception as exc:  # noqa: BLE001 - delivery problems must not break requests
            logger.error(
                "Security email delivery failed (template=%s, id=%s, error_type=%s).",
                template, delivery_id, type(exc).__name__,
            )

    def flush(self, timeout: float = 10.0) -> None:
        """Wait for queued deliveries (tests and graceful shutdown)."""
        with self._lock:
            pending = list(self._pending)
        wait(pending, timeout=timeout)

    def close(self) -> None:
        self.flush()
        self._executor.shutdown(wait=False)


def build_mailer(settings) -> Mailer:  # noqa: ANN001 - Settings import would be circular
    if settings.mail_backend == "smtp":
        transport: MailTransport | None = SmtpTransport(
            settings.smtp_host,
            settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password,
            security=settings.smtp_security,
        )
    elif settings.mail_backend == "outbox":
        transport = OutboxTransport(settings.mail_outbox_dir)
    else:
        transport = None
    return Mailer(transport, settings.mail_from, app_name="SCAP")
