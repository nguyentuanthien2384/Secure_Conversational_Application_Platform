# storage.py
from __future__ import annotations

from typing import Any
from database.models import *
from database.database import Database

class Memory:
    """Lớp dịch vụ thao tác hội thoại: sử dụng Database, **không** có SQL."""

    def __init__(self, db: Database) -> None:
        self.db: Database = db

    # Conveniences ở tầng nghiệp vụ

    def start_session(self, title: str | None = None) -> Session:
        return self.db.create_session(title=title)

    def add_user_message(self, session_id: str, content: str, meta: dict[str, Any] | None = None) -> Message:
        return self.db.insert_message(MessageCreate(session_id=session_id, role=Role.user, content=content, meta=meta or {}))

    def add_assistant_message(self, session_id: str, content: str, meta: dict[str, Any] | None = None) -> Message:
        return self.db.insert_message(MessageCreate(session_id=session_id, role=Role.assistant, content=content, meta=meta or {}))

    def history(self, session_id: str, limit: int | None = None) -> list[Message]:
        return self.db.fetch_messages(session_id, order="asc", limit=limit)

    def as_chat_list(self, session_id: str, limit: int | None = None) -> list[dict[str, Any]]:
        """Chuyển hội thoại thành [{role, content, meta}] để feed vào model."""
        msgs = self.history(session_id, limit=limit)
        return [{"role": m.role.value, "content": m.content, "meta": m.meta} for m in msgs]