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
import os
import re
import secrets
import smtplib
import ssl
import stat
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, parseaddr
from pathlib import Path
from typing import Protocol

from .private_storage import (
    PrivateStorageError,
    check_private_file,
    create_private_file,
    prepare_private_directory,
)

logger = logging.getLogger("secure_chat.mail")

MAIL_BACKENDS = ("disabled", "outbox", "smtp")
MAX_MESSAGE_BYTES = 65_536
_OUTBOX_LOCK = threading.Lock()
_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


class MailUnavailable(RuntimeError):
    """Email delivery is not configured for this deployment."""


class MailBusy(MailUnavailable):
    """The finite mail budget is full, or delivery has been stopped."""


def _positive_limit(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer.")
    return value


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
    """Keep a finite, private demo outbox; existing messages are never deleted.

    The quota is serialized across instances in this process. The outbox is a
    development transport, not a shared production spool across workers.
    """

    def __init__(
        self,
        directory: str | Path,
        *,
        max_files: int = 512,
        max_bytes: int = 16_777_216,
    ) -> None:
        # Keep the lexical path: resolving here would hide a symlink/junction.
        self.directory = Path(os.path.abspath(directory))
        self.max_files = _positive_limit(max_files, "max_files")
        self.max_bytes = _positive_limit(max_bytes, "max_bytes")

    def _prepare_directory(self) -> None:
        try:
            prepare_private_directory(self.directory)
        except PrivateStorageError as exc:
            raise MailUnavailable(
                "The demo outbox must use a private, unlinked directory. "
                "Create a new directory with scripts.local_storage mkdir."
            ) from exc

    def _check_quota(self, incoming_bytes: int) -> None:
        count = total = 0
        with os.scandir(self.directory) as entries:
            for entry in entries:
                # DirEntry.stat on Windows does not populate the hard-link
                # count; os.stat requests the complete file metadata.
                metadata = os.stat(entry.path, follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise MailUnavailable("The demo outbox contains an unsafe entry.")
                # Windows traversal permissions do not protect pre-existing
                # children with their own broad ACL. Validate retained mail too.
                try:
                    check_private_file(Path(entry.path))
                except PrivateStorageError as exc:
                    raise MailUnavailable("The demo outbox contains a non-private entry.") from exc
                count += 1
                total += metadata.st_size
                if count >= self.max_files or total + incoming_bytes > self.max_bytes:
                    raise MailBusy("The demo outbox budget is full.")
        if incoming_bytes > self.max_bytes:
            raise MailBusy("The demo outbox budget is full.")

    def send(self, message: EmailMessage) -> None:
        payload = bytes(message)
        if len(payload) > MAX_MESSAGE_BYTES:
            raise MailUnavailable("Security email exceeds its size budget.")
        with _OUTBOX_LOCK:
            self._prepare_directory()
            self._check_quota(len(payload))
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            path = self.directory / f"{stamp}-{secrets.token_hex(16)}.eml"
            try:
                # The ACL/mode is applied by the create operation, before any
                # reset/verification code is written to disk.
                with create_private_file(path) as output:
                    output.write(payload)
            except PrivateStorageError as exc:
                raise MailUnavailable("The demo outbox cannot securely create mail.") from exc


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
        max_pending: int = 32,
    ) -> None:
        name, address = parseaddr(sender)
        if normalize_email(address) is None:
            raise ValueError("MAIL_FROM phải là một địa chỉ email hợp lệ.")
        self.transport = transport
        self.sender = formataddr((name or app_name, address))
        self.app_name = app_name
        self.background = background
        self.max_pending = _positive_limit(max_pending, "max_pending")
        self._executor: ThreadPoolExecutor | None = None
        self._pending: set[Future] = set()
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)
        self._active = self._rejected = self._delivered = self._failed = 0
        self._closed = False

    @property
    def enabled(self) -> bool:
        return self.transport is not None

    def snapshot(self) -> dict[str, int | bool]:
        """Return process-local capacity/counters without mail addresses or content."""
        with self._lock:
            return {
                "limit": self.max_pending,
                "active": self._active,
                "rejected": self._rejected,
                "delivered": self._delivered,
                "failed": self._failed,
                "closed": self._closed,
            }

    def start(self) -> None:
        """Allow a new application lifespan once old deliveries have finished."""
        with self._lock:
            if self._active:
                if self._closed:
                    raise MailBusy("Previous email deliveries are still stopping.")
                return
            self._closed = False

    def send(self, to: str, subject: str, body: str, *, template: str) -> None:
        if self.transport is None:
            raise MailUnavailable("Email delivery is not configured.")
        if normalize_email(to) is None or len(body) > MAX_MESSAGE_BYTES:
            raise MailUnavailable("Security email is invalid or exceeds its size budget.")
        message = EmailMessage()
        message["From"] = self.sender
        message["To"] = to
        message["Subject"] = f"[{self.app_name}] {subject}"
        message["Message-ID"] = make_msgid(domain=self.sender.rpartition("@")[2].rstrip(">"))
        message["Auto-Submitted"] = "auto-generated"
        message.set_content(body)
        if len(bytes(message)) > MAX_MESSAGE_BYTES:
            raise MailUnavailable("Security email exceeds its size budget.")
        delivery_id = secrets.token_hex(6)
        with self._lock:
            if self._closed or self._active >= self.max_pending:
                self._rejected += 1
                raise MailBusy("Security email delivery is temporarily busy.")
            self._active += 1
        if not self.background:
            try:
                if not self._deliver(message, template, delivery_id):
                    raise MailUnavailable("Security email delivery is temporarily unavailable.")
            finally:
                with self._lock:
                    self._active -= 1
                    self._idle.notify_all()
            return
        try:
            with self._lock:
                # Closing may have begun while the message was being built.
                if self._closed:
                    self._rejected += 1
                    raise MailBusy("Security email delivery is temporarily busy.")
                if self._executor is None:
                    self._executor = ThreadPoolExecutor(
                        max_workers=2, thread_name_prefix="scap-mail"
                    )
                future = self._executor.submit(self._deliver, message, template, delivery_id)
                self._pending.add(future)
        except BaseException:
            with self._lock:
                self._active -= 1
                self._idle.notify_all()
            raise
        future.add_done_callback(self._forget)

    def _forget(self, future: Future) -> None:
        with self._lock:
            self._pending.discard(future)
            self._active -= 1
            self._idle.notify_all()

    def _deliver(self, message: EmailMessage, template: str, delivery_id: str) -> bool:
        try:
            self.transport.send(message)  # type: ignore[union-attr]
            with self._lock:
                self._delivered += 1
            logger.info("Security email delivered (template=%s, id=%s).", template, delivery_id)
            return True
        except Exception as exc:  # noqa: BLE001 - delivery problems must not break requests
            with self._lock:
                self._failed += 1
            logger.error(
                "Security email delivery failed (template=%s, id=%s, error_type=%s).",
                template, delivery_id, type(exc).__name__,
            )
            return False

    def flush(self, timeout: float = 10.0) -> None:
        """Wait for queued deliveries (tests and graceful shutdown)."""
        # Future.wait may return before its done callbacks have released the
        # slot. Waiting for our own accounting also includes synchronous work.
        with self._idle:
            self._idle.wait_for(lambda: self._active == 0, timeout=max(0.0, timeout))

    def close(self, timeout: float = 10.0) -> None:
        """Reject new work, allow bounded draining, then cancel queued messages."""
        with self._lock:
            self._closed = True
            executor, self._executor = self._executor, None
        self.flush(timeout=timeout)
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)


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
        transport = OutboxTransport(
            settings.mail_outbox_dir,
            max_files=getattr(settings, "mail_outbox_max_files", 512),
            max_bytes=getattr(settings, "mail_outbox_max_bytes", 16_777_216),
        )
    else:
        transport = None
    return Mailer(
        transport, settings.mail_from, app_name="SCAP",
        max_pending=getattr(settings, "mail_max_pending", 32),
    )
