"""Opt-in security housekeeping, independent of requests and admin polling.

PostgreSQL holds a session advisory lock throughout each cycle (including
commits). Redis coordinates the cadence and alert suppression across workers.
SQLite development deployments use a process mutex and must run one worker.
No anomaly in this service blocks an address, revokes a session, or runs a
host/container command. Existing request-time prevention remains separate.
"""

from __future__ import annotations

import asyncio
import hashlib
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import redis
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.app.audit_checkpoint import AuditCheckpointError, AuditCheckpointService
from src.app.config import Settings
from src.app.db import utcnow
from src.app.ids import detect_anomalies
from src.app.retention import enforce_retention
from src.app.siem import emit_security_event

_LOCAL_RUN_LOCK = threading.Lock()
# Distinct from the transaction lock used by audit-chain appends.
_ADVISORY_LOCK_ID = 0x5343_4150_4D41_494E
_MAX_LOCAL_ALERTS = 4_096


class SecurityMaintenance:
    """Lifespan-owned loop. ``start`` is synchronous; ``stop`` must be awaited.

    Every operation opens its own short-lived SQLAlchemy session. Shutdown
    drains the current cycle before the caller disposes the database engine;
    cancelling a to_thread task would leave a live writer using that engine.
    ``run_once`` also obeys cadence/coordination and is useful for manual tests.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        session_factory: Callable[[], Session],
        checkpoint_service: AuditCheckpointService | None = None,
        clear_crypto_cache: Callable[[], None] | None = None,
    ) -> None:
        self.settings = settings
        self.session_factory = session_factory
        self.checkpoint_service = checkpoint_service
        self.clear_crypto_cache = clear_crypto_cache
        if not 10 <= settings.security_maintenance_interval_seconds <= 86_400:
            raise ValueError("Maintenance interval must be between 10 and 86400 seconds.")
        if not 1 <= settings.security_maintenance_batch_size <= 5_000:
            raise ValueError("Maintenance batch size must be between 1 and 5000.")
        if not 1 <= settings.security_maintenance_anomaly_window_minutes <= 1_440:
            raise ValueError("Maintenance anomaly window must be between 1 and 1440 minutes.")
        with session_factory() as db:
            self.engine = db.get_bind()
        # Use stable database identity, never credentials, in coordination keys.
        identity = self.engine.url.set(password=None).render_as_string(hide_password=True)
        self._namespace = "scap:maintenance:v1:" + hashlib.sha256(identity.encode()).hexdigest()
        self._redis = (
            redis.Redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=3,
                socket_timeout=3,
            )
            if settings.security_maintenance_enabled and settings.redis_url
            else None
        )
        self._run_lock = threading.Lock()
        self._alerts: dict[str, float] = {}
        self._next_run_at = 0.0
        self._task: asyncio.Task[None] | None = None
        self._stop: asyncio.Event | None = None
        self.last_result: dict[str, Any] | None = None

    def start(self) -> None:
        if not self.settings.security_maintenance_enabled or self._task is not None:
            return
        self._stop = asyncio.Event()
        self._task = asyncio.create_task(self._run(), name="security-maintenance")

    async def stop(self) -> None:
        if self._stop is not None:
            self._stop.set()
        if self._task is not None:
            try:
                await self._task
            finally:
                self._task = None
        if self._redis is not None:
            await asyncio.to_thread(self._redis.close)

    async def _run(self) -> None:
        assert self._stop is not None
        while not self._stop.is_set():
            await asyncio.to_thread(self.run_once)
            try:
                await asyncio.wait_for(
                    self._stop.wait(),
                    timeout=self.settings.security_maintenance_interval_seconds,
                )
            except asyncio.TimeoutError:
                pass

    @contextmanager
    def _exclusive_cycle(self) -> Iterator[bool]:
        if self.engine.dialect.name != "postgresql":
            acquired = _LOCAL_RUN_LOCK.acquire(blocking=False)
            try:
                yield acquired
            finally:
                if acquired:
                    _LOCAL_RUN_LOCK.release()
            return
        # Hold a separate connection: a retention/checkpoint commit must never
        # release the coordination lock halfway through a maintenance cycle.
        with self.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            acquired = bool(
                conn.scalar(
                    text("SELECT pg_try_advisory_lock(:lock_id)"),
                    {"lock_id": _ADVISORY_LOCK_ID},
                )
            )
            try:
                yield acquired
            finally:
                if acquired:
                    try:
                        conn.execute(
                            text("SELECT pg_advisory_unlock(:lock_id)"),
                            {"lock_id": _ADVISORY_LOCK_ID},
                        )
                    except Exception:
                        # Never return a session-locked connection to the pool.
                        conn.invalidate()
                        raise

    def _claim_alert(self, fingerprint: str) -> bool:
        ttl = self.settings.security_maintenance_anomaly_window_minutes * 60
        if self._redis is not None:
            return bool(self._redis.set(f"{self._namespace}:alert:{fingerprint}", "1", nx=True, ex=ttl))
        now = time.monotonic()
        self._alerts = {key: expiry for key, expiry in self._alerts.items() if expiry > now}
        if fingerprint in self._alerts:
            return False
        if len(self._alerts) >= _MAX_LOCAL_ALERTS:
            # Bounded development memory. Production Redis expires keys itself.
            del self._alerts[next(iter(self._alerts))]
        self._alerts[fingerprint] = now + ttl
        return True

    @staticmethod
    def _failure(phase: str, result: dict[str, Any]) -> None:
        result["status"] = "degraded"
        result["failed_phases"].append(phase)
        # Database and transport errors can include credentials. Never retain
        # exception text, traceback, URLs, raw audit details, or request input.
        emit_security_event(
            "security.maintenance.failure", outcome="failure", details={"phase": phase}
        )

    def _check_anomalies(self, result: dict[str, Any]) -> None:
        if not self.settings.ids_enabled:
            return
        with self.session_factory() as db:
            anomalies = detect_anomalies(
                db, window_minutes=self.settings.security_maintenance_anomaly_window_minutes
            )
        result["anomalies_detected"] = len(anomalies)
        for anomaly in anomalies:
            subject_hash = hashlib.sha256((anomaly.subject or "").encode()).hexdigest()
            # Rising counts alone do not produce alert storms. A severity
            # escalation gets a fresh alert even within the suppression window.
            fingerprint = hashlib.sha256(
                f"{anomaly.code}:{anomaly.severity}:{subject_hash}".encode()
            ).hexdigest()
            if not self._claim_alert(fingerprint):
                continue
            emit_security_event(
                "ids.anomaly",
                outcome="failure",
                details={
                    "code": anomaly.code,
                    "anomaly_severity": anomaly.severity,
                    "count": anomaly.count,
                    "window_minutes": anomaly.window_minutes,
                    "subject_sha256": subject_hash,
                    "response": "observe",
                },
            )
            result["anomalies_emitted"] += 1

    def _checkpoint(self, result: dict[str, Any]) -> None:
        if self.checkpoint_service is None:
            return
        with self.session_factory() as db:
            previous = self.checkpoint_service.verify_latest(db)
            # Do not conceal evidence of checkpoint tampering with a new anchor.
            if previous.present and not previous.intact:
                raise AuditCheckpointError("Existing audit checkpoint is not intact.")
            verification = self.checkpoint_service.ensure_latest_anchored(db, probe_external=True)
            if verification.latest_event_id is not None and not verification.intact:
                raise AuditCheckpointError("Audit checkpoint could not be verified.")
            result["checkpoint_unanchored_events"] = verification.unanchored_events
            result["checkpoint_externally_delivered"] = verification.externally_delivered

    def _retention(self, result: dict[str, Any]) -> None:
        if not self.settings.security_maintenance_retention_enabled:
            return
        with self.session_factory() as db:
            retained = enforce_retention(
                db,
                batch_size=self.settings.security_maintenance_batch_size,
                secure_retention_days=self.settings.secure_retention_days,
                confidential_retention_days=self.settings.confidential_retention_days,
            )
        result["retention"] = retained.as_dict()
        if retained.expired_sessions and self.clear_crypto_cache is not None:
            self.clear_crypto_cache()
        if any(value for key, value in retained.as_dict().items() if key != "dry_run"):
            emit_security_event("retention.sweep", details=retained.as_dict())

    def run_once(self) -> dict[str, Any]:
        if not self.settings.security_maintenance_enabled:
            return {"status": "disabled"}
        if not self._run_lock.acquire(blocking=False):
            return {"status": "busy"}
        result: dict[str, Any] = {
            "status": "completed",
            "started_at": utcnow().isoformat(),
            "failed_phases": [],
            "anomalies_detected": 0,
            "anomalies_emitted": 0,
        }
        try:
            now = time.monotonic()
            if now < self._next_run_at:
                return {"status": "not_due"}
            self._next_run_at = now + self.settings.security_maintenance_interval_seconds
            with self._exclusive_cycle() as acquired:
                if not acquired:
                    return {"status": "busy"}
                if self._redis is not None and not self._redis.set(
                    f"{self._namespace}:cycle",
                    "1",
                    nx=True,
                    ex=self.settings.security_maintenance_interval_seconds,
                ):
                    return {"status": "not_due"}
                # A failed phase rolls back its own session and cannot prevent
                # other independent controls from running in the same cycle.
                for name, operation in (
                    ("anomalies", self._check_anomalies),
                    ("checkpoint", self._checkpoint),
                    ("retention", self._retention),
                ):
                    try:
                        operation(result)
                    except Exception:
                        self._failure(name, result)
        except Exception:
            # Coordination failure skips work instead of silently running every
            # production worker as a leader during a Redis/PostgreSQL outage.
            self._failure("coordination", result)
        finally:
            self._run_lock.release()
        self.last_result = result.copy()
        return result
