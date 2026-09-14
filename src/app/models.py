from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.app.db import Base, utcnow


def uuid4_str() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(16), default="user", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    ai_data_consent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ai_consent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ai_consent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # TOTP multi-factor authentication. The seed is stored encrypted (AES-GCM,
    # field AAD) so a database leak alone does not expose enrollable secrets.
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_secret_nonce: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Per-user DEK used for account secrets. The DEK is wrapped by the selected
    # KMS/Vault provider; no KEK is stored in this table.
    secret_wrapped_dek: Mapped[str | None] = mapped_column(Text, nullable=True)
    secret_kek_uri: Mapped[str | None] = mapped_column(String(512), nullable=True)
    secret_kek_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    secret_crypto_epoch: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Highest TOTP time-counter already accepted; blocks replay within a step.
    mfa_last_counter: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    sessions: Mapped[list[ChatSession]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )
    auth_sessions: Mapped[list[AuthSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    recovery_codes: Mapped[list[MfaRecoveryCode]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class AuthSession(Base):
    """Server-side record for each issued JWT, enabling per-device revocation."""

    __tablename__ = "auth_sessions"
    __table_args__ = (
        Index("ix_auth_sessions_user_active", "user_id", "revoked_at"),
        Index(
            "ix_auth_sessions_family_active",
            "user_id",
            "session_family_id",
            "revoked_at",
        ),
    )

    jti: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    # Stable across access-token rotation. Revoking a device session therefore
    # also revokes a successor minted concurrently from the selected token.
    session_family_id: Mapped[str] = mapped_column(String(36), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # Thời điểm đăng nhập *gốc* của chuỗi phiên này. Mỗi lần /api/auth/refresh
    # xoay token, giá trị này được mang sang phiên mới, nên nó là mốc để áp trần
    # tuyệt đối. Không có nó, sliding session sẽ cho phép gia hạn vĩnh viễn và
    # một token bị đánh cắp có thể được giữ sống mãi.
    root_issued_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Recent password + MFA verification used for sensitive operations such as
    # export, MFA enrollment and device trust changes.
    last_step_up_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped[User] = relationship(back_populates="auth_sessions")


class ChatSession(Base):
    __tablename__ = "chat_sessions"
    __table_args__ = (
        CheckConstraint(
            "security_mode IN ('secure', 'confidential', 'private_e2ee')",
            name="ck_chat_sessions_security_mode",
        ),
        CheckConstraint(
            "data_classification IN "
            "('public', 'internal', 'confidential', 'highly_confidential', 'e2ee_private')",
            name="ck_chat_sessions_data_classification",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    title: Mapped[str] = mapped_column(String(120), default="Cuộc hội thoại mới", nullable=False)
    security_mode: Mapped[str] = mapped_column(String(24), default="secure", nullable=False)
    data_classification: Mapped[str] = mapped_column(
        String(32), default="internal", nullable=False
    )
    current_crypto_epoch: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    crypto_suite: Mapped[str] = mapped_column(
        String(32), default="legacy-aes-256-gcm", nullable=False
    )
    # Active envelope metadata is duplicated on the session for fast policy and
    # backup inspection. Historic epochs live in ``session_key_epochs``.
    wrapped_dek: Mapped[str | None] = mapped_column(Text, nullable=True)
    kek_uri: Mapped[str | None] = mapped_column(String(512), nullable=True)
    kek_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    retention_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    owner: Mapped[User] = relationship(back_populates="sessions")
    messages: Mapped[list[SecureMessage]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="SecureMessage.id"
    )
    key_epochs: Mapped[list[SessionKeyEpoch]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="SessionKeyEpoch.epoch"
    )
    members: Mapped[list[ConversationMember]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    e2ee_envelopes: Mapped[list[E2eeEnvelope]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class SecureMessage(Base):
    __tablename__ = "secure_messages"
    __table_args__ = (
        Index("ix_secure_messages_session_created", "session_id", "created_at"),
        UniqueConstraint("session_id", "message_index", name="uq_secure_message_index"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    # Generated before encryption and included in canonical AAD. This prevents
    # swapping two ciphertexts that share the same session and role.
    message_uuid: Mapped[str] = mapped_column(String(64), default=uuid4_str, nullable=False)
    message_index: Mapped[int] = mapped_column(Integer, nullable=False)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    crypto_epoch: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    encryption_scheme: Mapped[str] = mapped_column(
        String(24), default="legacy-v1", nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    session: Mapped[ChatSession] = relationship(back_populates="messages")


class SessionKeyEpoch(Base):
    """One KMS/Vault-wrapped conversation DEK for one crypto epoch."""

    __tablename__ = "session_key_epochs"
    __table_args__ = (
        UniqueConstraint("session_id", "epoch", name="uq_session_key_epoch"),
        CheckConstraint("epoch > 0", name="ck_session_key_epoch_positive"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("chat_sessions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    wrapped_dek: Mapped[str] = mapped_column(Text, nullable=False)
    kek_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    kek_version: Mapped[str] = mapped_column(String(128), nullable=False)
    crypto_suite: Mapped[str] = mapped_column(String(32), default="AES-256-GCM", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    session: Mapped[ChatSession] = relationship(back_populates="key_epochs")


class ConversationMember(Base):
    """Membership metadata for ciphertext-only E2EE conversations."""

    __tablename__ = "conversation_members"
    __table_args__ = (
        UniqueConstraint("session_id", "user_id", name="uq_conversation_member"),
        CheckConstraint("joined_epoch > 0", name="ck_member_joined_epoch_positive"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("chat_sessions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    role: Mapped[str] = mapped_column(String(16), default="member", nullable=False)
    joined_epoch: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    removed_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    session: Mapped[ChatSession] = relationship(back_populates="members")


class E2eeDevice(Base):
    """Public device material only; the server never stores private keys."""

    __tablename__ = "e2ee_devices"
    __table_args__ = (
        UniqueConstraint("user_id", "fingerprint", name="uq_e2ee_device_fingerprint"),
        CheckConstraint(
            "trust_state IN ('pending', 'trusted', 'revoked')",
            name="ck_e2ee_device_trust_state",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    display_name: Mapped[str] = mapped_column(String(80), nullable=False)
    identity_key_b64: Mapped[str] = mapped_column(Text, nullable=False)
    signed_prekey_b64: Mapped[str] = mapped_column(Text, nullable=False)
    signed_prekey_signature_b64: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(95), nullable=False)
    trust_state: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    approved_by_device_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("e2ee_devices.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class E2eeDeviceChallenge(Base):
    """Short-lived, single-use proof/approval challenge stored only as a hash."""

    __tablename__ = "e2ee_device_challenges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    challenge_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class E2eePreKey(Base):
    __tablename__ = "e2ee_prekeys"
    __table_args__ = (UniqueConstraint("device_id", "key_id", name="uq_e2ee_prekey"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("e2ee_devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    public_key_b64: Mapped[str] = mapped_column(Text, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class E2eeEnvelope(Base):
    """Opaque Double Ratchet/MLS payload; ciphertext is never decrypted server-side."""

    __tablename__ = "e2ee_envelopes"
    __table_args__ = (
        UniqueConstraint("replay_key", name="uq_e2ee_replay_guard"),
        Index("ix_e2ee_recipient_created", "recipient_device_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("chat_sessions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    sender_user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    sender_device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("e2ee_devices.id", ondelete="RESTRICT"), nullable=False
    )
    recipient_device_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("e2ee_devices.id", ondelete="CASCADE"), nullable=True
    )
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    message_kind: Mapped[str] = mapped_column(String(16), default="application", nullable=False)
    client_message_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # Hash of sender + recipient + client message id. It gives both SQLite and
    # PostgreSQL an atomic replay guard, including MLS rows whose recipient
    # device is NULL (where a normal composite UNIQUE would allow duplicates).
    replay_key: Mapped[str] = mapped_column(String(96), nullable=False)
    header_b64: Mapped[str] = mapped_column(Text, nullable=False)
    ciphertext_b64: Mapped[str] = mapped_column(Text, nullable=False)
    group_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    session: Mapped[ChatSession] = relationship(back_populates="e2ee_envelopes")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_created", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success", nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    # Tamper-evident hash chain (xem src/app/audit_chain.py). prev_hash liên kết
    # bản ghi này với bản ghi trước; entry_hash là HMAC-SHA256 của cả hai. Sửa
    # hoặc xóa một dòng sẽ làm gãy toàn bộ chuỗi phía sau và bị phát hiện.
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)


class AuditCheckpoint(Base):
    """Externally signable anchor that detects deletion of an audit-chain suffix."""

    __tablename__ = "audit_checkpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    last_event_id: Mapped[int] = mapped_column(Integer, unique=True, nullable=False, index=True)
    root_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    signer_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    signer_version: Mapped[str] = mapped_column(String(128), nullable=False)
    external_receipt: Mapped[str | None] = mapped_column(Text, nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class RevokedToken(Base):
    """Server-side JWT denylist used for logout and incident response in the course deployment."""

    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reason: Mapped[str] = mapped_column(String(32), default="logout", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class MfaRecoveryCode(Base):
    """Single-use backup codes for account recovery when the TOTP device is lost.

    Only the Argon2id hash of each code is stored, exactly like passwords, so the
    database never holds a usable backup credential in the clear.
    """

    __tablename__ = "mfa_recovery_codes"
    __table_args__ = (Index("ix_mfa_recovery_user_used", "user_id", "used_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4_str)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    code_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    user: Mapped[User] = relationship(back_populates="recovery_codes")
