# storage.py
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from typing import Any

from database.models import * 

class Database:
    """Quản lý SQLite và **độc quyền** mọi lệnh SQL.

    Bảng:
      - sessions(id TEXT PK, title TEXT, created_at TEXT, updated_at TEXT)
      - messages(id INTEGER PK, session_id TEXT FK, role TEXT, content TEXT, meta TEXT JSON, created_at TEXT)
      - kv_store(key TEXT PK, value TEXT, updated_at TEXT)

    Public API (chỉ trả/nhận Pydantic models & primitives, KHÔNG lộ SQL):
      -- Sessions
        create_session(title?, session_id?)
        get_session(session_id)
        list_sessions(limit=20, offset=0)
        update_session_title(session_id, title)
        touch_session(session_id)
        delete_session(session_id)

      -- Messages
        insert_message(payload: MessageCreate) -> Message
        fetch_messages(session_id, limit?, order="asc", since_id?) -> list[Message]
        search_messages(session_id, q, limit=50) -> list[Message]
        delete_message(message_id)
        clear_messages_by_session(session_id) -> int

      -- KV
        kv_set(key, value) -> KVItem
        kv_get(key, default=None) -> Any

      -- Export/Backup
        export_session_jsonl(session_id, out_path) -> int
        backup(to_path)
    """

    def __init__(self, path: str = "memory.db", init_schema: bool = True) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            self.path,
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._apply_pragmas()
        if init_schema:
            self._migrate()

    # ---------- Low-level utils (private) ----------

    def _apply_pragmas(self) -> None:
        with self._conn:
            _  = self._conn.execute("PRAGMA foreign_keys = ON;")
            _  = self._conn.execute("PRAGMA journal_mode = WAL;")
            _  = self._conn.execute("PRAGMA synchronous = NORMAL;")
            _  = self._conn.execute("PRAGMA busy_timeout = 5000;")

    def _migrate(self) -> None:
        with self._conn:
            _ = self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    title TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            _ = self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    meta TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
                );
                """
            )
            _ = self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_session_time ON messages(session_id, created_at);"
            )
            _ = self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS kv_store (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

    @contextmanager
    def transaction(self):
        with self._lock:
            try:
                _ = self._conn.execute("BEGIN;")
                yield
                _ = self._conn.execute("COMMIT;")
            except Exception:
                _ = self._conn.execute("ROLLBACK;")
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---------- Row -> Model helpers (private) ----------

    @staticmethod
    def _row_to_session(row: sqlite3.Row) -> Session:
        return Session.model_validate(dict(row))

    @staticmethod
    def _row_to_message(row: sqlite3.Row) -> Message:
        d = dict(row)
        d["role"] = Role(d["role"])
        return Message.model_validate(d)

    # ---------- Sessions (ALL SQL HERE) ----------

    def create_session(self, title: str | None = None, session_id: str | None = None) -> Session:
        sid = session_id or str(uuid.uuid4())
        now = utcnow_iso()
        with self._lock, self._conn:
            _ = self._conn.execute(
                "INSERT INTO sessions(id, title, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (sid, title, now, now),
            )
        return Session(id=sid, title=title, created_at=now, updated_at=now)

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, title, created_at, updated_at FROM sessions WHERE id = ? LIMIT 1;",
                (session_id,),
            )
            row = cur.fetchone()
        return self._row_to_session(row) if row else None

    def list_sessions(self, limit: int = 20, offset: int = 0) -> list[Session]:
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT id, title, created_at, updated_at
                FROM sessions
                ORDER BY updated_at DESC
                LIMIT ? OFFSET ?;
                """,
                (limit, offset),
            )
            rows = cur.fetchall()
        return [self._row_to_session(r) for r in rows]

    def update_session_title(self, session_id: str, title: str | None) -> Session | None:
        now = utcnow_iso()
        with self._lock, self._conn:
            _ = self._conn.execute(
                "UPDATE sessions SET title = ?, updated_at = ? WHERE id = ?",
                (title, now, session_id),
            )
        return self.get_session(session_id)

    def touch_session(self, session_id: str) -> None:
        with self._lock, self._conn:
            _ = self._conn.execute(
                "UPDATE sessions SET updated_at = ? WHERE id = ?",
                (utcnow_iso(), session_id),
            )

    def delete_session(self, session_id: str) -> None:
        with self._lock, self._conn:
            _ = self._conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))

    # ---------- Messages (ALL SQL HERE) ----------

    def insert_message(self, payload: MessageCreate) -> Message:
        now = utcnow_iso()
        meta_json = json.dumps(payload.meta or {}, ensure_ascii=False)
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                INSERT INTO messages(session_id, role, content, meta, created_at)
                VALUES (?, ?, ?, ?, ?);
                """,
                (payload.session_id, payload.role.value, payload.content, meta_json, now),
            )
            mid = cur.lastrowid
        # cập nhật updated_at phiên
        self.touch_session(payload.session_id)
        return Message(id=mid, session_id=payload.session_id, role=payload.role,
                       content=payload.content, meta=payload.meta, created_at=now)

    def fetch_messages(
        self,
        session_id: str,
        limit: int | None = None,
        order: str = "asc",
        since_id: int | None = None,
    ) -> list[Message]:
        clauses = ["session_id = ?"]
        params: list[Any] = [session_id]
        if since_id is not None:
            clauses.append("id > ?")
            params.append(since_id)
        order_sql = "ASC" if order.lower() == "asc" else "DESC"
        limit_sql = "" if limit is None else "LIMIT ?"
        if limit is not None:
            params.append(limit)

        sql = f"""
            SELECT id, session_id, role, content, meta, created_at
            FROM messages
            WHERE {' AND '.join(clauses)}
            ORDER BY id {order_sql}
            {limit_sql};
        """
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [self._row_to_message(r) for r in rows]

    def search_messages(self, session_id: str, q: str, limit: int = 50) -> list[Message]:
        like = f"%{q}%"
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT id, session_id, role, content, meta, created_at
                FROM messages
                WHERE session_id = ? AND content LIKE ?
                ORDER BY id ASC
                LIMIT ?;
                """,
                (session_id, like, limit),
            )
            rows = cur.fetchall()
        return [self._row_to_message(r) for r in rows]

    def delete_message(self, message_id: int) -> None:
        with self._lock, self._conn:
            _ = self._conn.execute("DELETE FROM messages WHERE id = ?", (message_id,))

    def clear_messages_by_session(self, session_id: str) -> int:
        """Xoá toàn bộ tin nhắn của một phiên. Trả về số bản ghi bị xoá (ước lượng)."""
        with self._lock:
            # Đếm sơ bộ
            cur = self._conn.execute("SELECT COUNT(*) AS c FROM messages WHERE session_id = ?", (session_id,))
            count = int(cur.fetchone()["c"])
        with self._lock, self._conn:
            _ = self._conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
            # chạm phiên để cập nhật mốc thời gian, giữ session
            _ = self._conn.execute("UPDATE sessions SET updated_at = ? WHERE id = ?", (utcnow_iso(), session_id))
        return count

    # ---------- KV Store (ALL SQL HERE) ----------

    def kv_set(self, key: str, value: Any) -> KVItem:
        now = utcnow_iso()
        payload = json.dumps(value, ensure_ascii=False)
        with self.transaction():
            _ = self._conn.execute(
                """
                INSERT INTO kv_store(key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;
                """,
                (key, payload, now),
            )
        return KVItem(key=key, value=value, updated_at=now)

    def kv_get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            cur = self._conn.execute("SELECT value FROM kv_store WHERE key = ? LIMIT 1;", (key,))
            row = cur.fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except Exception:
            return default

    # ---------- Export / Backup (ALL SQL HERE) ----------

    def export_session_jsonl(self, session_id: str, out_path: str) -> int:
        msgs = self.fetch_messages(session_id, order="asc")
        count = 0
        with open(out_path, "w", encoding="utf-8") as f:
            for m in msgs:
                f.write(m.model_dump_json() + "\n")
                count += 1
        return count

    def backup(self, to_path: str) -> None:
        with self._lock:
            dest = sqlite3.connect(to_path)
            with dest:
                self._conn.backup(dest)
            dest.close()
