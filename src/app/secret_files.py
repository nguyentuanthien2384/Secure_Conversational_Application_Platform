"""Read finite UTF-8 secrets through an ordinary, unlinked file handle.

Mounted service-owned/read-only files are supported; this reader does not
change their permissions or require ownership by the application user. Local
paths must be regular files, without symbolic links, junctions or hard links.
Callers normalize the returned text and never retain it in process environment.
"""

from __future__ import annotations

import os
from pathlib import Path

from src.app.private_storage import read_regular_file

MAX_SECRET_FILE_BYTES = 16_384


class SecretFileError(OSError):
    """A secret cannot be read safely; messages contain no paths or contents."""


class SecretFileTooLarge(SecretFileError):
    """A secret exceeded its finite byte budget."""


def read_secret_text(path: str | Path, *, max_bytes: int = MAX_SECRET_FILE_BYTES) -> str:
    """Read at most ``max_bytes + 1`` bytes, including if the file grows.

    The initial size check avoids reading known oversized inputs. The bounded
    read is still necessary: a credential file may grow after that check. The
    open helper rejects nonregular objects before any content read, avoiding
    FIFO/device waits, and keeps path/handle validation tied to the same object.
    """
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise ValueError("Secret file byte budget must be an integer.")
    if not 1 <= max_bytes <= MAX_SECRET_FILE_BYTES:
        raise ValueError("Secret file byte budget must be between 1 and 16384.")
    try:
        with read_regular_file(path) as source:
            if os.fstat(source.fileno()).st_size > max_bytes:
                raise SecretFileTooLarge("Secret file exceeds its byte budget.")
            payload = source.read(max_bytes + 1)
    except SecretFileTooLarge:
        raise
    except OSError:
        raise SecretFileError("Secret file cannot be read safely.") from None
    if len(payload) > max_bytes:
        raise SecretFileTooLarge("Secret file exceeds its byte budget.")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        raise SecretFileError("Secret file must contain valid UTF-8.") from None
