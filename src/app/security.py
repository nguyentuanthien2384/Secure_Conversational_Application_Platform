from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import threading
import time
import unicodedata
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class PasswordService:
    def __init__(self) -> None:
        self.hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
        # Used for unknown usernames so login timing does not reveal whether an
        # account exists. This is a fixed Argon2id hash, not an application secret.
        self.dummy_hash = self.hasher.hash("not-a-real-password")

    def hash(self, password: str) -> str:
        return self.hasher.hash(unicodedata.normalize("NFC", password))

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            return self.hasher.verify(password_hash, unicodedata.normalize("NFC", password))
        except (VerifyMismatchError, InvalidHashError):
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        try:
            return self.hasher.check_needs_rehash(password_hash)
        except InvalidHashError:
            return True


class TokenService:
    def __init__(self, secret_key: str, access_token_minutes: int = 30) -> None:
        self.secret_key = secret_key
        self.access_token_minutes = access_token_minutes
        self.algorithm = "HS256"

    def issue(self, user_id: str, username: str, role: str, token_version: int) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,
            "usr": username,
            "role": role,
            "ver": token_version,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=self.access_token_minutes),
            "jti": str(uuid.uuid4()),
            "iss": "secure-chat-course-project",
            "aud": "secure-chat-api",
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode(self, token: str) -> dict[str, Any]:
        return jwt.decode(
            token,
            self.secret_key,
            algorithms=[self.algorithm],
            audience="secure-chat-api",
            issuer="secure-chat-course-project",
            options={"require": ["exp", "iat", "nbf", "sub", "jti", "ver"]},
        )

    def issue_mfa_challenge(self, user_id: str, minutes: int = 5) -> str:
        """Short-lived token proving password step succeeded, pending a TOTP code.

        It uses a distinct audience so it can never be presented as an API access
        token, and carries no role/session, so it authorizes nothing on its own.
        """
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,
            "typ": "mfa_challenge",
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=minutes),
            "jti": str(uuid.uuid4()),
            "iss": "secure-chat-course-project",
            "aud": "secure-chat-mfa",
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode_mfa_challenge(self, token: str) -> dict[str, Any]:
        payload = jwt.decode(
            token,
            self.secret_key,
            algorithms=[self.algorithm],
            audience="secure-chat-mfa",
            issuer="secure-chat-course-project",
            options={"require": ["exp", "iat", "nbf", "sub", "jti"]},
        )
        if payload.get("typ") != "mfa_challenge":
            raise jwt.InvalidTokenError("Không phải token thử thách MFA.")
        return payload


class CryptoService:
    """AES-256-GCM encryption with associated data bound to session and role."""

    @staticmethod
    def _load_key(material_b64: str, label: str) -> bytes:
        try:
            key = base64.urlsafe_b64decode(material_b64.strip().encode("ascii"))
        except Exception as exc:
            raise ValueError(f"{label} phải là URL-safe base64 hợp lệ.") from exc
        if len(key) != 32:
            raise ValueError(f"{label} phải giải mã thành đúng 32 byte (AES-256).")
        return key

    def __init__(
        self,
        master_key_b64: str = "",
        key_version: int = 1,
        *,
        keyring: dict[int, str] | None = None,
        active_key_version: int | None = None,
    ) -> None:
        """Hold one *active* key for encryption plus every retired key for decryption.

        Passing only ``master_key_b64`` keeps the original single-key behaviour.
        Passing ``keyring={1: "...", 2: "..."}`` enables key rotation (Bài 4 —
        quản lý vòng đời khóa): new ciphertext is written under the active
        version while historic rows stay readable under their own version, so a
        rotation never requires downtime or a big-bang re-encryption.
        """
        material: dict[int, str] = dict(keyring or {})
        if master_key_b64:
            material.setdefault(key_version, master_key_b64)
        if not material:
            raise ValueError(
                "Cần ít nhất một khóa mã hóa (MASTER_ENCRYPTION_KEY hoặc MASTER_ENCRYPTION_KEYS)."
            )

        self._keys: dict[int, bytes] = {
            version: self._load_key(value, f"MASTER_ENCRYPTION_KEY (v{version})")
            for version, value in material.items()
        }
        self._ciphers: dict[int, AESGCM] = {
            version: AESGCM(key) for version, key in self._keys.items()
        }

        chosen = active_key_version if active_key_version is not None else max(self._keys)
        if chosen not in self._keys:
            raise ValueError(f"ACTIVE_KEY_VERSION={chosen} không có trong keyring.")
        self.key_version = chosen
        self.key = self._keys[chosen]
        self.aesgcm = self._ciphers[chosen]

    @property
    def known_key_versions(self) -> tuple[int, ...]:
        return tuple(sorted(self._keys))

    def _cipher_for(self, version: int) -> AESGCM:
        cipher = self._ciphers.get(version)
        if cipher is None:
            raise ValueError(
                f"Không hỗ trợ key version {version}. "
                f"Các version đang nạp: {', '.join(str(v) for v in self.known_key_versions)}."
            )
        return cipher

    @staticmethod
    def _aad(session_id: str, role: str, key_version: int) -> bytes:
        return f"secure-chat|{session_id}|{role}|v{key_version}".encode()

    @staticmethod
    def _field_aad(context: str, key_version: int) -> bytes:
        # A separate AAD namespace ("field") keeps encrypted account secrets from
        # ever being interchangeable with chat message ciphertexts.
        return f"secure-chat|field|{context}|v{key_version}".encode()

    def encrypt_secret(self, plaintext: str, context: str) -> tuple[str, str]:
        """Encrypt a sensitive account field (e.g. a TOTP seed) at rest.

        ``context`` is bound into the AAD so a ciphertext copied onto another
        user or field fails authentication instead of decrypting silently.
        """
        nonce = secrets.token_bytes(12)
        ciphertext = self.aesgcm.encrypt(
            nonce,
            plaintext.encode("utf-8"),
            self._field_aad(context, self.key_version),
        )
        return (
            base64.urlsafe_b64encode(ciphertext).decode("ascii"),
            base64.urlsafe_b64encode(nonce).decode("ascii"),
        )

    def decrypt_secret(self, ciphertext_b64: str, nonce_b64: str, context: str) -> str:
        try:
            ciphertext = base64.urlsafe_b64decode(ciphertext_b64.encode("ascii"))
            nonce = base64.urlsafe_b64decode(nonce_b64.encode("ascii"))
        except Exception as exc:
            raise ValueError("Bí mật đã lưu không hợp lệ hoặc đã bị thay đổi.") from exc
        # Account fields carry no version column, so try the active key first and
        # then fall back through retired keys during a rotation window.
        versions = [self.key_version] + [
            v for v in self.known_key_versions if v != self.key_version
        ]
        for version in versions:
            try:
                plaintext = self._ciphers[version].decrypt(
                    nonce,
                    ciphertext,
                    self._field_aad(context, version),
                )
                return plaintext.decode("utf-8")
            except (InvalidTag, UnicodeDecodeError):
                continue
        raise ValueError("Bí mật đã lưu không hợp lệ hoặc đã bị thay đổi.")

    def encrypt(self, plaintext: str, session_id: str, role: str) -> tuple[str, str, int]:
        nonce = secrets.token_bytes(12)
        ciphertext = self.aesgcm.encrypt(
            nonce,
            plaintext.encode("utf-8"),
            self._aad(session_id, role, self.key_version),
        )
        return (
            base64.urlsafe_b64encode(ciphertext).decode("ascii"),
            base64.urlsafe_b64encode(nonce).decode("ascii"),
            self.key_version,
        )

    def decrypt(
        self,
        ciphertext_b64: str,
        nonce_b64: str,
        session_id: str,
        role: str,
        key_version: int,
    ) -> str:
        cipher = self._cipher_for(key_version)
        try:
            ciphertext = base64.urlsafe_b64decode(ciphertext_b64.encode("ascii"))
            nonce = base64.urlsafe_b64decode(nonce_b64.encode("ascii"))
            plaintext = cipher.decrypt(
                nonce,
                ciphertext,
                self._aad(session_id, role, key_version),
            )
            return plaintext.decode("utf-8")
        except (ValueError, InvalidTag, UnicodeDecodeError) as exc:
            raise ValueError("Dữ liệu mã hóa không hợp lệ hoặc đã bị thay đổi.") from exc


class TotpService:
    """Time-based one-time password (RFC 6238) using only the standard library.

    The algorithm is implemented from scratch rather than pulled from a package so
    the report can explain HOTP/TOTP directly: HMAC-SHA1 over an 8-byte counter,
    dynamic truncation, then modulo 10**digits. ``verify`` returns the matched time
    counter so the caller can persist it and reject replay of the same code.
    """

    def __init__(self, *, digits: int = 6, period: int = 30, algorithm: str = "sha1") -> None:
        if digits < 6 or digits > 8:
            raise ValueError("Số chữ số TOTP phải nằm trong khoảng 6-8.")
        self.digits = digits
        self.period = period
        self.algorithm = algorithm

    @staticmethod
    def generate_secret(num_bytes: int = 20) -> str:
        """Return a base32 secret (no padding), the format authenticator apps expect."""
        return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")

    def _hotp(self, secret_b32: str, counter: int) -> str:
        padding = "=" * (-len(secret_b32) % 8)
        key = base64.b32decode(secret_b32.upper() + padding, casefold=True)
        digest = hmac.new(key, struct.pack(">Q", counter), self.algorithm).digest()
        offset = digest[-1] & 0x0F
        binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(binary % (10**self.digits)).zfill(self.digits)

    def _counter(self, timestamp: float | None = None) -> int:
        return int((timestamp if timestamp is not None else time.time()) // self.period)

    def now_code(self, secret_b32: str, timestamp: float | None = None) -> str:
        return self._hotp(secret_b32, self._counter(timestamp))

    def verify(
        self,
        secret_b32: str,
        code: str,
        *,
        valid_window: int = 1,
        timestamp: float | None = None,
        after_counter: int | None = None,
    ) -> int | None:
        """Return the matched time counter, or ``None`` if the code is invalid.

        ``valid_window`` tolerates limited clock skew on either side. ``after_counter``
        enforces monotonicity so a code that was already accepted cannot be replayed.
        """
        candidate = (code or "").strip().replace(" ", "")
        if len(candidate) != self.digits or not candidate.isdigit():
            return None
        current = self._counter(timestamp)
        for offset in range(-valid_window, valid_window + 1):
            counter = current + offset
            if counter < 0:
                continue
            if after_counter is not None and counter <= after_counter:
                continue
            if hmac.compare_digest(self._hotp(secret_b32, counter), candidate):
                return counter
        return None

    def provisioning_uri(self, secret_b32: str, account_name: str, issuer: str) -> str:
        """Build the otpauth:// URI that seeds authenticator apps (also as a QR)."""
        label = quote(f"{issuer}:{account_name}")
        params = (
            f"secret={secret_b32}"
            f"&issuer={quote(issuer)}"
            f"&algorithm={self.algorithm.upper()}"
            f"&digits={self.digits}"
            f"&period={self.period}"
        )
        return f"otpauth://totp/{label}?{params}"


def generate_recovery_code() -> str:
    """Human-typeable single-use backup code, e.g. ``a1b2c3-d4e5f6``."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"  # no ambiguous 0/o/1/l/i
    part = lambda: "".join(secrets.choice(alphabet) for _ in range(6))  # noqa: E731
    return f"{part()}-{part()}"


class PwnedPasswordChecker:
    """Screen passwords against Have I Been Pwned using k-anonymity (SHA-1 range API).

    Only the first five hex chars of the SHA-1 are ever sent, so the plaintext and
    full hash never leave the process. Network failures fail *open* (treated as
    not-breached) so an outage cannot block all sign-ups; callers should log that.
    """

    _API = "https://api.pwnedpasswords.com/range/"

    def __init__(self, *, enabled: bool = False, timeout: float = 2.0) -> None:
        self.enabled = enabled
        self.timeout = timeout

    def is_compromised(self, password: str) -> bool:
        if not self.enabled:
            return False
        import urllib.error
        import urllib.request

        # The HIBP range protocol mandates SHA-1; it is not used for password storage.
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # nosec B324
        prefix, suffix = sha1[:5], sha1[5:]
        # The base URL is a fixed HTTPS constant; only a five-character hash prefix is appended.
        request = urllib.request.Request(  # nosec B310
            self._API + prefix,
            headers={"User-Agent": "secure-chat-course-project", "Add-Padding": "true"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # nosec B310
                body = response.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, OSError):
            return False  # fail open on any network problem
        for line in body.splitlines():
            candidate, _, count = line.partition(":")
            if candidate.strip().upper() == suffix and count.strip() not in ("", "0"):
                return True
        return False


class SlidingWindowRateLimiter:
    """Small in-memory limiter for a single teaching/demo instance."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, max_attempts: int, window_seconds: int) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= max_attempts:
                retry_after = max(1, int(window_seconds - (now - bucket[0])))
                return False, retry_after
            bucket.append(now)
            return True, 0

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


class RedisSlidingWindowRateLimiter:
    """Atomic Redis-backed limiter shared by every application worker."""

    _ALLOW_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local maximum = tonumber(ARGV[3])
local member = ARGV[4]
local cutoff = now - window

redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local count = redis.call('ZCARD', key)
if count >= maximum then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = 1
    if oldest[2] then
        retry_after = math.max(1, math.ceil(window - (now - tonumber(oldest[2]))))
    end
    return {0, retry_after}
end

redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, math.ceil(window) + 1)
return {1, 0}
"""

    def __init__(self, redis_url: str, *, key_prefix: str = "scap:rate-limit:") -> None:
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - exercised only in Redis deployments
            raise RuntimeError("Thiếu package redis cho REDIS_URL.") from exc
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        try:
            self._client.ping()
        except redis.RedisError as exc:
            raise RuntimeError("Không thể kết nối Redis cho rate limit.") from exc
        self._key_prefix = key_prefix

    def allow(self, key: str, max_attempts: int, window_seconds: int) -> tuple[bool, int]:
        result = self._client.eval(
            self._ALLOW_SCRIPT,
            1,
            self._key_prefix + key,
            time.time(),
            window_seconds,
            max_attempts,
            secrets.token_urlsafe(18),
        )
        return bool(int(result[0])), int(result[1])

    def reset(self, key: str) -> None:
        self._client.delete(self._key_prefix + key)


def safe_json(data: dict[str, Any] | None) -> str:
    if not data:
        return "{}"
    cleaned: dict[str, Any] = {}
    for key, value in data.items():
        safe_key = str(key).replace("\r", " ").replace("\n", " ")[:80]
        if isinstance(value, str):
            cleaned[safe_key] = value.replace("\r", " ").replace("\n", " ")[:500]
        elif isinstance(value, (int, float, bool)) or value is None:
            cleaned[safe_key] = value
        else:
            cleaned[safe_key] = str(value)[:500]
    return json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"))
