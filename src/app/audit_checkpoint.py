"""Externally anchored checkpoints for the tamper-evident audit chain.

The local HMAC chain detects edits and middle-row deletion, but its remaining
tail becomes the new apparent tail if an attacker deletes every event after a
chosen point. A checkpoint commits the latest event id/hash to a separately
retained HTTPS/WORM sink, giving an external observer a monotonic anchor.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.app.audit_chain import canonical_datetime
from src.app.db import utcnow
from src.app.models import AuditCheckpoint, AuditEvent

CHECKPOINT_NAMESPACE = uuid.UUID("995c6f15-89fb-47bb-b5b6-067562f076f1")
EXTERNAL_FAILURE_RETRY_SECONDS = 30


class AuditCheckpointError(RuntimeError):
    """Checkpoint creation or delivery failed without leaking sink details."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Never forward the WORM bearer token to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ARG002
        return None


def derive_checkpoint_key(secret_key: str) -> bytes:
    return hashlib.sha256(
        ("secure-chat:audit-checkpoint:v1:" + secret_key).encode("utf-8")
    ).digest()


def canonical_checkpoint(
    *, checkpoint_id: str, last_event_id: int, root_hash: str, created_at: datetime
) -> bytes:
    if last_event_id < 1 or len(root_hash) != 64:
        raise ValueError("Audit checkpoint fields are invalid.")
    payload = {
        "format": "scap-audit-checkpoint-v1",
        "checkpoint_id": checkpoint_id,
        "last_event_id": last_event_id,
        "root_hash": root_hash,
        "created_at": canonical_datetime(created_at),
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_checkpoint(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class CheckpointVerification:
    present: bool
    intact: bool
    externally_delivered: bool
    last_event_id: int | None = None
    latest_event_id: int | None = None
    unanchored_events: int = 0
    fresh: bool = False
    fully_anchored: bool = False
    reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "checkpoint_present": self.present,
            "checkpoint_intact": self.intact,
            "checkpoint_externally_delivered": self.externally_delivered,
            "checkpoint_last_event_id": self.last_event_id,
            "checkpoint_latest_event_id": self.latest_event_id,
            "checkpoint_unanchored_events": self.unanchored_events,
            "checkpoint_fresh": self.fresh,
            "checkpoint_fully_anchored": self.fully_anchored,
            "checkpoint_reason": self.reason,
        }


class AuditCheckpointService:
    def __init__(
        self,
        secret_key: str,
        *,
        interval: int = 100,
        endpoint: str = "",
        token_file: str = "",
        timeout_seconds: float = 5.0,
        max_unanchored_events: int = 100,
        probe_interval_seconds: int = 300,
    ) -> None:
        if interval < 1:
            raise ValueError("Audit checkpoint interval must be positive.")
        if max_unanchored_events < 0:
            raise ValueError("Maximum unanchored audit events cannot be negative.")
        if probe_interval_seconds < 1:
            raise ValueError("Audit WORM probe interval must be positive.")
        self.key = derive_checkpoint_key(secret_key)
        self.interval = interval
        self.max_unanchored_events = max_unanchored_events
        self.probe_interval_seconds = probe_interval_seconds
        self.endpoint = endpoint.strip()
        self.token_file = Path(token_file) if token_file else None
        self.timeout_seconds = timeout_seconds
        self._delivery_lock = threading.RLock()
        self._last_external_success_monotonic: float | None = None
        self._last_external_failure_monotonic: float | None = None
        if self.endpoint:
            parsed = urlparse(self.endpoint)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.fragment
            ):
                raise ValueError("AUDIT_WORM_ENDPOINT must be a credential-free HTTPS URL.")
            if self.token_file is None:
                raise ValueError("AUDIT_WORM_TOKEN_FILE is required for a remote sink.")
            # Fail readiness immediately if the append-only sink credential was
            # not mounted correctly. The token value is never retained.
            self._token()

    def _token(self) -> str:
        if self.token_file is None:
            return ""
        try:
            token = self.token_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise AuditCheckpointError("Audit WORM credential is unavailable.") from exc
        if not token or len(token) > 4096 or "\r" in token or "\n" in token:
            raise AuditCheckpointError("Audit WORM credential is invalid.")
        return token

    def _deliver(self, document: dict[str, object], checkpoint_id: str) -> str:
        body = json.dumps(document, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._token()}",
            "Idempotency-Key": checkpoint_id,
        }
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            headers=headers,
            method="POST",
        )
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            _RejectRedirects(),
        )
        try:
            # The endpoint is fixed HTTPS and redirects are rejected so the
            # bearer credential cannot cross origins.
            with opener.open(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                response_body = response.read(16_385)
                if len(response_body) > 16_384 or not 200 <= response.status < 300:
                    raise AuditCheckpointError("Audit WORM sink rejected the checkpoint.")
                # Persist only a digest of the untrusted response, never its
                # content. The remote system remains the authoritative copy.
                return "sha256:" + hashlib.sha256(response_body).hexdigest()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AuditCheckpointError("Audit WORM delivery failed.") from exc

    @staticmethod
    def _document(checkpoint: AuditCheckpoint) -> dict[str, object]:
        signed_payload = canonical_checkpoint(
            checkpoint_id=checkpoint.id,
            last_event_id=checkpoint.last_event_id,
            root_hash=checkpoint.root_hash,
            created_at=checkpoint.created_at,
        )
        document: dict[str, object] = json.loads(signed_payload)
        document["signature"] = checkpoint.signature
        document["signer"] = checkpoint.signer_uri
        return document

    def _delivery_succeeded(self) -> None:
        self._last_external_success_monotonic = time.monotonic()
        self._last_external_failure_monotonic = None

    def _delivery_failed(self) -> None:
        self._last_external_failure_monotonic = time.monotonic()

    def _failure_backoff_active(self) -> bool:
        last_failure = self._last_external_failure_monotonic
        return (
            last_failure is not None
            and time.monotonic() - last_failure < EXTERNAL_FAILURE_RETRY_SECONDS
        )

    def _probe_is_due(self) -> bool:
        last_success = self._last_external_success_monotonic
        return (
            last_success is None
            or time.monotonic() - last_success >= self.probe_interval_seconds
        )

    def _anchor(self, db: Session) -> AuditCheckpoint | None:
        latest_event = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
        if latest_event is None or not latest_event.entry_hash:
            return None
        # Cache scalar values before a commit/rollback can expire ORM state.
        # This keeps the concurrent-insert recovery path deterministic on every
        # SQLAlchemy backend, including PostgreSQL deployments.
        latest_event_id = latest_event.id
        latest_event_hash = latest_event.entry_hash
        latest_event_created_at = latest_event.created_at or utcnow()
        existing = db.scalar(
            select(AuditCheckpoint).where(AuditCheckpoint.last_event_id == latest_event_id)
        )
        if existing is not None:
            return existing
        # A deterministic id makes a retry safe when the receiver persisted the
        # checkpoint but its response was lost. The WORM endpoint sees the same
        # Idempotency-Key instead of a second logical anchor.
        checkpoint_id = str(
            uuid.uuid5(
                CHECKPOINT_NAMESPACE,
                f"{latest_event_id}:{latest_event_hash}",
            )
        )
        # Bind the complete payload to the sealed event so independent workers
        # derive the same signature as well as the same idempotency key.
        created_at = latest_event_created_at
        signed_payload = canonical_checkpoint(
            checkpoint_id=checkpoint_id,
            last_event_id=latest_event_id,
            root_hash=latest_event_hash,
            created_at=created_at,
        )
        signature = sign_checkpoint(self.key, signed_payload)
        document: dict[str, object] = json.loads(signed_payload)
        document["signature"] = signature
        document["signer"] = "hmac-sha256://scap/audit-checkpoint-v1"
        receipt = None
        delivered_at = None
        if self.endpoint:
            try:
                receipt = self._deliver(document, checkpoint_id)
            except AuditCheckpointError:
                self._delivery_failed()
                raise
            delivered_at = utcnow()
            self._delivery_succeeded()
        checkpoint = AuditCheckpoint(
            id=checkpoint_id,
            last_event_id=latest_event_id,
            root_hash=latest_event_hash,
            signature=signature,
            signer_uri="hmac-sha256://scap/audit-checkpoint-v1",
            signer_version="v1",
            external_receipt=receipt,
            delivered_at=delivered_at,
            created_at=created_at,
        )
        db.add(checkpoint)
        try:
            db.commit()
            db.refresh(checkpoint)
        except IntegrityError as exc:
            db.rollback()
            # Another worker may have delivered and inserted the same
            # deterministic checkpoint concurrently. Accept only an exact,
            # externally delivered match; any conflict is suspicious.
            concurrent = db.scalar(
                select(AuditCheckpoint).where(
                    AuditCheckpoint.last_event_id == latest_event_id
                )
            )
            if (
                concurrent is not None
                and concurrent.id == checkpoint_id
                and concurrent.root_hash == latest_event_hash
                and concurrent.signature == signature
                and (not self.endpoint or concurrent.delivered_at is not None)
            ):
                if self.endpoint:
                    self._delivery_succeeded()
                return concurrent
            raise AuditCheckpointError("Could not persist the audit checkpoint.") from exc
        except Exception as exc:
            db.rollback()
            raise AuditCheckpointError("Could not persist the audit checkpoint.") from exc
        return checkpoint

    def anchor(self, db: Session) -> AuditCheckpoint | None:
        # Serialize delivery and insertion within one process. The deterministic
        # idempotency key provides the corresponding protection across workers.
        with self._delivery_lock:
            return self._anchor(db)

    def maybe_anchor(self, db: Session, event: AuditEvent) -> AuditCheckpoint | None:
        latest = db.scalar(
            select(AuditCheckpoint).order_by(AuditCheckpoint.last_event_id.desc()).limit(1)
        )
        last_anchored = latest.last_event_id if latest is not None else 0
        if event.id - last_anchored < self.interval:
            return None
        return self.anchor(db)

    def ensure_latest_anchored(
        self,
        db: Session,
        *,
        probe_external: bool = False,
    ) -> CheckpointVerification:
        """Catch up an audit tail and optionally prove the WORM sink is reachable.

        Replaying an already delivered checkpoint uses its deterministic
        idempotency key and does not modify the append-only local table. A
        readiness probe can therefore detect an idle sink outage without
        manufacturing new checkpoints or weakening database grants.
        """

        with self._delivery_lock:
            # This method backs the public readiness endpoint. Cache a recent
            # failure so callers cannot turn an outage into unbounded outbound
            # TLS attempts; direct/admin anchoring remains explicitly retryable.
            if probe_external and self.endpoint and self._failure_backoff_active():
                raise AuditCheckpointError("Audit WORM delivery is temporarily unavailable.")
            verification = self.verify_latest(db)
            if verification.latest_event_id is None:
                return verification

            if not verification.fully_anchored:
                self._anchor(db)
                verification = self.verify_latest(db)

            if (
                probe_external
                and self.endpoint
                and verification.fully_anchored
                and self._probe_is_due()
            ):
                checkpoint = db.scalar(
                    select(AuditCheckpoint)
                    .order_by(AuditCheckpoint.last_event_id.desc())
                    .limit(1)
                )
                if checkpoint is None:
                    return verification
                try:
                    self._deliver(self._document(checkpoint), checkpoint.id)
                except AuditCheckpointError:
                    self._delivery_failed()
                    raise
                self._delivery_succeeded()

            return verification

    def verify_latest(self, db: Session) -> CheckpointVerification:
        # Avoid returning cached ORM values after an out-of-band edit and keep
        # latest-id/tail-count telemetry within one database statement.
        db.expire_all()
        checkpoint = db.scalar(
            select(AuditCheckpoint).order_by(AuditCheckpoint.last_event_id.desc()).limit(1)
        )
        if checkpoint is None:
            latest_event_id, unanchored_events = db.execute(
                select(func.max(AuditEvent.id), func.count(AuditEvent.id))
            ).one()
            return CheckpointVerification(
                present=False,
                intact=False,
                externally_delivered=False,
                latest_event_id=latest_event_id,
                unanchored_events=unanchored_events,
                reason="missing_checkpoint",
            )
        latest_event_id, unanchored_events = db.execute(
            select(
                func.max(AuditEvent.id),
                func.count(AuditEvent.id).filter(AuditEvent.id > checkpoint.last_event_id),
            )
        ).one()
        event = db.get(AuditEvent, checkpoint.last_event_id)
        delivered = checkpoint.delivered_at is not None and bool(checkpoint.external_receipt)
        if event is None:
            return CheckpointVerification(
                present=True,
                intact=False,
                externally_delivered=delivered,
                last_event_id=checkpoint.last_event_id,
                latest_event_id=latest_event_id,
                unanchored_events=unanchored_events,
                reason="anchored_event_missing",
            )
        payload = canonical_checkpoint(
            checkpoint_id=checkpoint.id,
            last_event_id=checkpoint.last_event_id,
            root_hash=checkpoint.root_hash,
            created_at=checkpoint.created_at,
        )
        expected = sign_checkpoint(self.key, payload)
        if not secrets.compare_digest(expected, checkpoint.signature):
            return CheckpointVerification(
                present=True,
                intact=False,
                externally_delivered=delivered,
                last_event_id=checkpoint.last_event_id,
                latest_event_id=latest_event_id,
                unanchored_events=unanchored_events,
                reason="checkpoint_signature_mismatch",
            )
        if not event.entry_hash or not secrets.compare_digest(
            event.entry_hash,
            checkpoint.root_hash,
        ):
            return CheckpointVerification(
                present=True,
                intact=False,
                externally_delivered=delivered,
                last_event_id=checkpoint.last_event_id,
                latest_event_id=latest_event_id,
                unanchored_events=unanchored_events,
                reason="checkpoint_root_mismatch",
            )
        fresh = unanchored_events <= self.max_unanchored_events
        fully_anchored = delivered and unanchored_events == 0
        return CheckpointVerification(
            present=True,
            intact=True,
            externally_delivered=delivered,
            last_event_id=checkpoint.last_event_id,
            latest_event_id=latest_event_id,
            unanchored_events=unanchored_events,
            fresh=fresh,
            fully_anchored=fully_anchored,
        )
