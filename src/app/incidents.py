"""Bounded analyst workflow using verified application audit evidence.

Containment is an analyst-recorded checkpoint. This module never modifies a
firewall, blocklist, user, session or original audit entry. Snapshots contain
only correlation metadata, not request bodies or free-form audit details.
"""

from __future__ import annotations

import hmac
import logging
import re
import uuid
from collections.abc import Callable
from datetime import timezone

from fastapi import HTTPException, Request
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from src.app.audit import client_ip, client_user_agent, safe_user_agent
from src.app.audit_chain import append_lock, compute_hash, entry_canonical, seal_event
from src.app.db import utcnow
from src.app.dlp import DLPScanner
from src.app.models import AuditEvent, IncidentEvidence, IncidentTransition, SecurityIncident
from src.app.schemas import IncidentCreate, IncidentDetailResponse, IncidentUpdate
from src.app.security import safe_json
from src.app.siem import emit_security_event

_TITLE_SCANNER = DLPScanner()
logger = logging.getLogger("secure_chat.incidents")


def _require_audit_key(request: Request) -> bytes:
    key = getattr(request.app.state, "audit_key", None)
    if key is None:
        raise HTTPException(status_code=409, detail="Hồ sơ sự cố cần bật chuỗi audit đã niêm phong.")
    return key


def _utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _commit_change(
    db: Session, request: Request, key: bytes, actor_id: str,
    incident_id: str, event_type: str, details: dict, change: Callable[[], None],
) -> None:
    """Serialize before taking the DB write lock and commit decision + audit.

    record_audit acquires the non-reentrant append lock itself. This scoped
    writer uses the same sealing primitive while holding that lock across the
    case mutation; acquiring it after INSERT/UPDATE could deadlock with an
    unrelated audit writer on SQLite.
    """
    event = AuditEvent(
        actor_id=actor_id, event_type=event_type, target_type="security_incident",
        target_id=incident_id, outcome="success", ip_address=client_ip(request),
        user_agent=safe_user_agent(client_user_agent(request)),
        request_id=getattr(request.state, "request_id", None), details_json=safe_json(details),
    )
    with append_lock(db):
        try:
            change()
            seal_event(db, event, key)
            db.add(event)
            db.commit()
            db.refresh(event)
        except Exception:
            db.rollback()
            raise
    emit_security_event(
        event.event_type, outcome=event.outcome, actor_id=event.actor_id,
        target_type=event.target_type, target_id=event.target_id,
        source_ip=event.ip_address, user_agent=event.user_agent,
        request_id=event.request_id, audit_id=event.id, entry_hash=event.entry_hash,
        details=details,
    )
    checkpoint_service = getattr(request.app.state, "audit_checkpoint_service", None)
    if checkpoint_service is not None:
        try:
            checkpoint_service.maybe_anchor(db, event)
        except Exception:  # noqa: BLE001 - committed evidence survives a sink outage
            logger.error("Incident checkpoint delivery failed audit_id=%s", event.id)
            emit_security_event(
                "audit.checkpoint.delivery_failed", outcome="failure",
                audit_id=event.id, entry_hash=event.entry_hash, request_id=event.request_id,
            )


def incident_detail(db: Session, incident: SecurityIncident) -> IncidentDetailResponse:
    evidence = db.scalars(
        select(IncidentEvidence)
        .where(IncidentEvidence.incident_id == incident.id)
        .order_by(IncidentEvidence.audit_id)
        .limit(20)
    ).all()
    transitions = db.scalars(
        select(IncidentTransition)
        .where(IncidentTransition.incident_id == incident.id)
        .order_by(IncidentTransition.version)
        .limit(4)
    ).all()
    return IncidentDetailResponse(
        id=incident.id, title=incident.title, stage=incident.stage,
        severity=incident.severity, status=incident.status, version=incident.version,
        created_at=_utc(incident.created_at), updated_at=_utc(incident.updated_at),
        evidence_count=incident.evidence_count,
        evidence=[{
            "audit_id": row.audit_id, "event_type": row.event_type,
            "outcome": row.outcome, "request_id": row.request_id,
            "created_at": _utc(row.created_at), "entry_hash": row.entry_hash,
        } for row in evidence],
        transitions=[{
            "from_status": row.from_status, "to_status": row.to_status,
            "actor_id": row.actor_id, "created_at": _utc(row.created_at),
            "resolution": row.resolution,
        } for row in transitions],
    )


def get_incident(db: Session, incident_id: str) -> SecurityIncident:
    incident = db.get(SecurityIncident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy hồ sơ sự cố.")
    return incident


def create_incident(
    db: Session, request: Request, actor_id: str, payload: IncidentCreate,
) -> IncidentDetailResponse:
    key = _require_audit_key(request)
    if _TITLE_SCANNER.scan(payload.title):
        raise HTTPException(status_code=422, detail="Dùng tiêu đề ngắn không chứa bí mật hoặc dữ liệu cá nhân.")
    evidence = db.scalars(
        select(AuditEvent).where(AuditEvent.id.in_(payload.evidence_ids)).order_by(AuditEvent.id)
    ).all()
    if len(evidence) != len(payload.evidence_ids):
        raise HTTPException(status_code=422, detail="Chỉ chọn audit ID hiện có đã được niêm phong.")
    for row in evidence:
        # Verify exactly the selected entries, without a full audit-table scan.
        if not re.fullmatch(r"[0-9a-f]{64}", row.entry_hash or "") or not re.fullmatch(
            r"[0-9a-f]{64}", row.prev_hash or ""
        ) or not hmac.compare_digest(
            row.entry_hash, compute_hash(key, row.prev_hash, entry_canonical(row))
        ):
            raise HTTPException(status_code=422, detail="Bằng chứng audit chưa niêm phong hoặc không còn hợp lệ.")
    incident = SecurityIncident(
        id=str(uuid.uuid4()), title=payload.title, stage=payload.stage, severity=payload.severity,
        status="new", version=1, evidence_count=len(evidence),
    )

    def write_case():
        db.add(incident)
        db.flush()
        db.add_all(IncidentEvidence(
            incident_id=incident.id, audit_id=row.id, event_type=row.event_type,
            outcome=row.outcome, request_id=row.request_id,
            created_at=row.created_at, entry_hash=row.entry_hash,
        ) for row in evidence)
        db.add(IncidentTransition(
            incident_id=incident.id, version=1, from_status=None, to_status="new", actor_id=actor_id,
        ))

    _commit_change(
        db, request, key, actor_id, incident.id, "incident.created",
        {"stage": incident.stage, "severity": incident.severity,
         "version": 1, "evidence_count": incident.evidence_count}, write_case,
    )
    return incident_detail(db, incident)


def transition_incident(
    db: Session, request: Request, actor_id: str,
    incident_id: str, payload: IncidentUpdate,
) -> IncidentDetailResponse:
    key = _require_audit_key(request)
    incident = get_incident(db, incident_id)
    if incident.version != payload.version:
        raise HTTPException(status_code=409, detail="Hồ sơ đã đổi; tải lại trước khi cập nhật.")
    old_status = incident.status
    allowed = (
        (old_status, payload.status) in {
            ("new", "investigating"), ("investigating", "contained"),
        }
        or (old_status == "contained" and payload.status == "closed"
            and payload.resolution == "confirmed")
        or (old_status == "investigating" and payload.status == "closed"
            and payload.resolution in {"false_positive", "duplicate"})
    )
    if not allowed:
        raise HTTPException(status_code=409, detail="Trạng thái hoặc kết luận không phù hợp quy trình điều tra.")
    now = utcnow()

    def write_transition():
        changed = db.execute(
            update(SecurityIncident)
            .where(SecurityIncident.id == incident_id,
                   SecurityIncident.version == payload.version,
                   SecurityIncident.status == old_status)
            .values(status=payload.status, version=payload.version + 1, updated_at=now)
            .execution_options(synchronize_session=False)
        )
        if changed.rowcount != 1:
            raise HTTPException(status_code=409, detail="Hồ sơ đã đổi; tải lại trước khi cập nhật.")
        db.add(IncidentTransition(
            incident_id=incident_id, version=payload.version + 1,
            from_status=old_status, to_status=payload.status, actor_id=actor_id,
            resolution=payload.resolution, created_at=now,
        ))

    _commit_change(
        db, request, key, actor_id, incident_id, "incident.status_changed",
        {"from_status": old_status, "to_status": payload.status,
         "version": payload.version + 1, "resolution": payload.resolution,
         "containment_is_analyst_checkpoint": payload.status == "contained"}, write_transition,
    )
    db.refresh(incident)
    return incident_detail(db, incident)
