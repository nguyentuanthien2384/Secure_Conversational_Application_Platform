# models.py
from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, ConfigDict, field_validator, field_serializer


# =========================
# Pydantic Models & Enums
# =========================

class Role(str, Enum):
    user = "user"
    assistant = "model"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Session(BaseModel):
    """Thông tin một phiên hội thoại."""
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(description="UUID4 dưới dạng chuỗi")
    title: str | None = None
    created_at: datetime
    updated_at: datetime

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def _parse_dt(cls, v):
        # Cho phép truyền TEXT ISO từ SQLite -> datetime
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v


class Message(BaseModel):
    """Một tin nhắn trong phiên."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    session_id: str
    role: Role
    content: str
    meta: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    @field_validator("created_at", mode="before")
    @classmethod
    def _parse_dt(cls, v):
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v

    @field_validator("meta", mode="before")
    @classmethod
    def _parse_meta(cls, v):
        # Hỗ trợ cả JSON string từ DB lẫn dict đã parse
        if v is None or v == "":
            return {}
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return {}
        return v

    @field_serializer("meta")
    def _dump_meta(self, v):
        # Khi .model_dump(mode="json") sẽ serialize meta thành dict (không ép JSON string)
        return v


class MessageCreate(BaseModel):
    """Payload tạo message mới."""
    session_id: str
    role: Role
    content: str
    meta: dict[str, Any] = Field(default_factory=dict)


class KVItem(BaseModel):
    """Bản ghi key-value đơn giản."""
    key: str
    value: Any
    updated_at: datetime

    @field_validator("updated_at", mode="before")
    @classmethod
    def _parse_dt(cls, v):
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v