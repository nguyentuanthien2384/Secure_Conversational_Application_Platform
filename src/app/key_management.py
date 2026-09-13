"""Envelope-encryption key providers.

The application encrypts conversation data with random 256-bit data-encryption
keys (DEKs).  A provider protects those DEKs with a key-encryption key (KEK)
that is kept outside the database.  Provider failures are deliberately
fail-closed: callers must never fall back to plaintext or to an unrelated key.

``LocalAesKeyProvider`` exists for development, tests and legacy migration.  A
high-sensitivity production deployment should use Vault Transit, AWS KMS or
Google Cloud KMS with workload identity and least-privilege permissions.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote, urlparse

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_SAFE_VAULT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Never forward Vault credentials to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ARG002
        return None


class KeyProviderError(RuntimeError):
    """A KEK operation failed without exposing provider or secret details."""


@dataclass(frozen=True)
class WrappedDek:
    wrapped_dek: str
    kek_uri: str
    kek_version: str


@dataclass(frozen=True)
class GeneratedDek(WrappedDek):
    plaintext_dek: bytes


@runtime_checkable
class KeyProvider(Protocol):
    """Vendor-neutral interface used by the envelope-encryption layer."""

    @property
    def provider_name(self) -> str: ...

    @property
    def kek_uri(self) -> str: ...

    def generate_wrapped_dek(self, *, context: dict[str, str]) -> GeneratedDek: ...

    def unwrap_dek(
        self,
        wrapped_dek: str,
        *,
        context: dict[str, str],
        kek_uri: str,
        kek_version: str,
    ) -> bytes: ...

    def rewrap_dek(
        self,
        wrapped_dek: str,
        *,
        context: dict[str, str],
        kek_uri: str,
        kek_version: str,
    ) -> WrappedDek: ...


def canonical_context(context: dict[str, str]) -> bytes:
    """Return an unambiguous, versioned encryption context."""
    cleaned = {str(key): str(value) for key, value in context.items()}
    if not cleaned or any(not key or len(key) > 80 for key in cleaned):
        raise ValueError("Encryption context must contain non-empty bounded keys.")
    document = {"format": "scap-kms-context-v1", "context": cleaned}
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64decode(value: str, *, label: str) -> bytes:
    try:
        return base64.b64decode(
            value.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise KeyProviderError(f"{label} is not valid base64.") from exc


class LocalAesKeyProvider:
    """AES-GCM KEK adapter for development and deterministic migration tests."""

    def __init__(
        self,
        keys: dict[str, bytes],
        *,
        active_version: str,
        key_uri: str = "local://scap/development-kek",
    ) -> None:
        if not keys or active_version not in keys:
            raise ValueError("Local keyring must contain its active version.")
        if any(len(key) != 32 for key in keys.values()):
            raise ValueError("Every local KEK must contain exactly 32 bytes.")
        self._keys = dict(keys)
        self._active_version = str(active_version)
        self._kek_uri = key_uri

    @classmethod
    def from_base64_keyring(
        cls,
        keys: dict[int, str],
        *,
        active_version: int,
        key_uri: str = "local://scap/development-kek",
    ) -> LocalAesKeyProvider:
        decoded = {
            str(version): _b64decode(material, label=f"Local KEK v{version}")
            for version, material in keys.items()
        }
        return cls(decoded, active_version=str(active_version), key_uri=key_uri)

    @property
    def provider_name(self) -> str:
        return "local"

    @property
    def kek_uri(self) -> str:
        return self._kek_uri

    def _wrap(self, dek: bytes, context: dict[str, str]) -> WrappedDek:
        nonce = secrets.token_bytes(12)
        cipher = AESGCM(self._keys[self._active_version])
        ciphertext = cipher.encrypt(nonce, dek, canonical_context(context))
        return WrappedDek(
            wrapped_dek=_b64encode(nonce + ciphertext),
            kek_uri=self._kek_uri,
            kek_version=self._active_version,
        )

    def generate_wrapped_dek(self, *, context: dict[str, str]) -> GeneratedDek:
        dek = secrets.token_bytes(32)
        wrapped = self._wrap(dek, context)
        return GeneratedDek(
            plaintext_dek=dek,
            wrapped_dek=wrapped.wrapped_dek,
            kek_uri=wrapped.kek_uri,
            kek_version=wrapped.kek_version,
        )

    def unwrap_dek(
        self,
        wrapped_dek: str,
        *,
        context: dict[str, str],
        kek_uri: str,
        kek_version: str,
    ) -> bytes:
        if not secrets.compare_digest(kek_uri, self._kek_uri):
            raise KeyProviderError("Stored KEK URI does not match the configured provider.")
        key = self._keys.get(str(kek_version))
        if key is None:
            raise KeyProviderError("The required local KEK version is unavailable.")
        payload = _b64decode(wrapped_dek, label="Wrapped DEK")
        if len(payload) < 12 + 16:
            raise KeyProviderError("Wrapped DEK is truncated.")
        try:
            dek = AESGCM(key).decrypt(payload[:12], payload[12:], canonical_context(context))
        except (InvalidTag, ValueError) as exc:
            raise KeyProviderError("Wrapped DEK authentication failed.") from exc
        if len(dek) != 32:
            raise KeyProviderError("Provider returned an invalid DEK length.")
        return dek

    def rewrap_dek(
        self,
        wrapped_dek: str,
        *,
        context: dict[str, str],
        kek_uri: str,
        kek_version: str,
    ) -> WrappedDek:
        dek = self.unwrap_dek(
            wrapped_dek,
            context=context,
            kek_uri=kek_uri,
            kek_version=kek_version,
        )
        try:
            return self._wrap(dek, context)
        finally:
            # ``bytes`` cannot be reliably zeroized in CPython.  Keep the value
            # in this narrow scope and never retain/log it.
            del dek


class VaultTransitKeyProvider:
    """HashiCorp Vault Transit adapter using its datakey/decrypt/rewrap APIs."""

    def __init__(
        self,
        *,
        address: str,
        token_file: str,
        key_name: str,
        mount: str = "transit",
        namespace: str = "",
        timeout_seconds: float = 5.0,
        allow_insecure_http: bool = False,
    ) -> None:
        parsed = urlparse(address.rstrip("/"))
        if parsed.scheme not in ({"http", "https"} if allow_insecure_http else {"https"}):
            raise ValueError("Vault address must use HTTPS.")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Vault address must not contain credentials, query or fragment.")
        if not parsed.hostname:
            raise ValueError("Vault address is invalid.")
        if not _SAFE_VAULT_NAME.fullmatch(mount) or not _SAFE_VAULT_NAME.fullmatch(key_name):
            raise ValueError("Vault mount and key name contain unsupported characters.")
        if not token_file:
            raise ValueError(
                "Vault token file is required; do not embed the token in configuration."
            )
        normalized_namespace = namespace.strip()
        if len(normalized_namespace) > 256 or any(
            ord(character) < 32 or ord(character) == 127 for character in normalized_namespace
        ):
            raise ValueError("Vault namespace contains unsupported characters.")
        self._address = address.rstrip("/")
        self._token_file = Path(token_file)
        self._mount = mount
        self._key_name = key_name
        self._namespace = normalized_namespace
        self._timeout = timeout_seconds
        self._allow_insecure_http = allow_insecure_http
        self._kek_uri = f"vault://{mount}/{key_name}"
        # Fail during startup when the mounted workload credential is absent or
        # malformed, rather than serving until the first KMS operation fails.
        # The value is deliberately not retained.
        self._token()

    @property
    def provider_name(self) -> str:
        return "vault"

    @property
    def kek_uri(self) -> str:
        return self._kek_uri

    def _token(self) -> str:
        try:
            token = self._token_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise KeyProviderError("Vault workload token is unavailable.") from exc
        if not token or len(token) > 4096 or "\n" in token or "\r" in token:
            raise KeyProviderError("Vault workload token is invalid.")
        return token

    def _post(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = (
            f"{self._address}/v1/{quote(self._mount, safe='')}/{operation}/"
            f"{quote(self._key_name, safe='')}"
        )
        headers = {
            "Content-Type": "application/json",
            "X-Vault-Token": self._token(),
        }
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        request = urllib.request.Request(
            url,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        ssl_context = ssl.create_default_context()
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_context),
            _RejectRedirects(),
        )
        try:
            # The origin is validated above and redirects are rejected so the
            # workload token cannot be forwarded to another host.
            with opener.open(
                request,
                timeout=self._timeout,
            ) as response:
                document = json.loads(response.read(1_048_577))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            raise KeyProviderError("Vault Transit operation failed.") from exc
        data = document.get("data") if isinstance(document, dict) else None
        if not isinstance(data, dict):
            raise KeyProviderError("Vault Transit returned an invalid response.")
        return data

    @staticmethod
    def _version(ciphertext: str) -> str:
        parts = ciphertext.split(":", 2)
        return parts[1] if len(parts) == 3 and parts[0] == "vault" else "unknown"

    def _assert_uri(self, kek_uri: str) -> None:
        if not secrets.compare_digest(kek_uri, self._kek_uri):
            raise KeyProviderError("Stored KEK URI does not match the configured Vault key.")

    def generate_wrapped_dek(self, *, context: dict[str, str]) -> GeneratedDek:
        data = self._post(
            "datakey/plaintext",
            {"bits": 256, "context": base64.b64encode(canonical_context(context)).decode()},
        )
        try:
            plaintext = base64.b64decode(data["plaintext"], validate=True)
            ciphertext = str(data["ciphertext"])
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise KeyProviderError("Vault Transit returned an invalid data key.") from exc
        if len(plaintext) != 32 or not ciphertext.startswith("vault:v"):
            raise KeyProviderError("Vault Transit returned an invalid data key.")
        return GeneratedDek(
            plaintext_dek=plaintext,
            wrapped_dek=ciphertext,
            kek_uri=self._kek_uri,
            kek_version=self._version(ciphertext),
        )

    def unwrap_dek(
        self,
        wrapped_dek: str,
        *,
        context: dict[str, str],
        kek_uri: str,
        kek_version: str,
    ) -> bytes:
        del kek_version
        self._assert_uri(kek_uri)
        data = self._post(
            "decrypt",
            {
                "ciphertext": wrapped_dek,
                "context": base64.b64encode(canonical_context(context)).decode(),
            },
        )
        try:
            plaintext = base64.b64decode(data["plaintext"], validate=True)
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise KeyProviderError("Vault Transit returned an invalid plaintext key.") from exc
        if len(plaintext) != 32:
            raise KeyProviderError("Vault Transit returned an invalid DEK length.")
        return plaintext

    def rewrap_dek(
        self,
        wrapped_dek: str,
        *,
        context: dict[str, str],
        kek_uri: str,
        kek_version: str,
    ) -> WrappedDek:
        del kek_version
        self._assert_uri(kek_uri)
        data = self._post(
            "rewrap",
            {
                "ciphertext": wrapped_dek,
                "context": base64.b64encode(canonical_context(context)).decode(),
            },
        )
        ciphertext = data.get("ciphertext")
        if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:v"):
            raise KeyProviderError("Vault Transit returned an invalid rewrapped key.")
        return WrappedDek(ciphertext, self._kek_uri, self._version(ciphertext))


class AwsKmsKeyProvider:
    """AWS KMS adapter; the optional boto3 package is loaded only when selected."""

    def __init__(self, *, key_id: str, region: str = "") -> None:
        if not key_id:
            raise ValueError("AWS KMS key ID is required.")
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - optional production adapter
            raise RuntimeError("Install the optional boto3 package to use AWS KMS.") from exc
        self._client = boto3.client("kms", region_name=region or None)
        self._key_id = key_id
        self._region = region or "default"
        self._kek_uri = f"aws-kms://{self._region}/{key_id}"

    @property
    def provider_name(self) -> str:
        return "aws-kms"

    @property
    def kek_uri(self) -> str:
        return self._kek_uri

    @staticmethod
    def _context(context: dict[str, str]) -> dict[str, str]:
        return {"scap-format": "v1", **{str(k): str(v) for k, v in context.items()}}

    def generate_wrapped_dek(self, *, context: dict[str, str]) -> GeneratedDek:
        try:
            result = self._client.generate_data_key(
                KeyId=self._key_id,
                KeySpec="AES_256",
                EncryptionContext=self._context(context),
            )
            plaintext = bytes(result["Plaintext"])
            wrapped = _b64encode(bytes(result["CiphertextBlob"]))
        except Exception as exc:  # noqa: BLE001 - SDK exception hierarchy is optional
            raise KeyProviderError("AWS KMS data-key generation failed.") from exc
        if len(plaintext) != 32:
            raise KeyProviderError("AWS KMS returned an invalid DEK length.")
        return GeneratedDek(plaintext, wrapped, self._kek_uri, str(result.get("KeyId", "current")))

    def unwrap_dek(
        self,
        wrapped_dek: str,
        *,
        context: dict[str, str],
        kek_uri: str,
        kek_version: str,
    ) -> bytes:
        del kek_version
        if not secrets.compare_digest(kek_uri, self._kek_uri):
            raise KeyProviderError("Stored KEK URI does not match the configured AWS KMS key.")
        try:
            result = self._client.decrypt(
                KeyId=self._key_id,
                CiphertextBlob=_b64decode(wrapped_dek, label="Wrapped DEK"),
                EncryptionContext=self._context(context),
            )
            plaintext = bytes(result["Plaintext"])
        except Exception as exc:  # noqa: BLE001
            raise KeyProviderError("AWS KMS unwrap failed.") from exc
        if len(plaintext) != 32:
            raise KeyProviderError("AWS KMS returned an invalid DEK length.")
        return plaintext

    def rewrap_dek(
        self,
        wrapped_dek: str,
        *,
        context: dict[str, str],
        kek_uri: str,
        kek_version: str,
    ) -> WrappedDek:
        del kek_version
        if not secrets.compare_digest(kek_uri, self._kek_uri):
            raise KeyProviderError("Stored KEK URI does not match the configured AWS KMS key.")
        try:
            result = self._client.re_encrypt(
                CiphertextBlob=_b64decode(wrapped_dek, label="Wrapped DEK"),
                SourceEncryptionContext=self._context(context),
                DestinationKeyId=self._key_id,
                DestinationEncryptionContext=self._context(context),
            )
            ciphertext = _b64encode(bytes(result["CiphertextBlob"]))
        except Exception as exc:  # noqa: BLE001
            raise KeyProviderError("AWS KMS rewrap failed.") from exc
        return WrappedDek(ciphertext, self._kek_uri, str(result.get("KeyId", "current")))


class GcpKmsKeyProvider:
    """Google Cloud KMS adapter; credentials come from workload identity/ADC."""

    def __init__(self, *, key_name: str) -> None:
        if not key_name:
            raise ValueError("Google Cloud KMS key resource name is required.")
        try:
            from google.cloud import kms  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - optional production adapter
            raise RuntimeError("Install google-cloud-kms to use Google Cloud KMS.") from exc
        self._client = kms.KeyManagementServiceClient()
        self._key_name = key_name
        self._kek_uri = f"gcp-kms://{key_name}"

    @property
    def provider_name(self) -> str:
        return "gcp-kms"

    @property
    def kek_uri(self) -> str:
        return self._kek_uri

    def _wrap(self, dek: bytes, context: dict[str, str]) -> WrappedDek:
        try:
            result = self._client.encrypt(
                request={
                    "name": self._key_name,
                    "plaintext": dek,
                    "additional_authenticated_data": canonical_context(context),
                }
            )
        except Exception as exc:  # noqa: BLE001
            raise KeyProviderError("Google Cloud KMS wrap failed.") from exc
        return WrappedDek(_b64encode(bytes(result.ciphertext)), self._kek_uri, "current")

    def generate_wrapped_dek(self, *, context: dict[str, str]) -> GeneratedDek:
        plaintext = secrets.token_bytes(32)
        wrapped = self._wrap(plaintext, context)
        return GeneratedDek(plaintext, wrapped.wrapped_dek, wrapped.kek_uri, wrapped.kek_version)

    def unwrap_dek(
        self,
        wrapped_dek: str,
        *,
        context: dict[str, str],
        kek_uri: str,
        kek_version: str,
    ) -> bytes:
        del kek_version
        if not secrets.compare_digest(kek_uri, self._kek_uri):
            raise KeyProviderError("Stored KEK URI does not match the configured GCP KMS key.")
        try:
            result = self._client.decrypt(
                request={
                    "name": self._key_name,
                    "ciphertext": _b64decode(wrapped_dek, label="Wrapped DEK"),
                    "additional_authenticated_data": canonical_context(context),
                }
            )
            plaintext = bytes(result.plaintext)
        except Exception as exc:  # noqa: BLE001
            raise KeyProviderError("Google Cloud KMS unwrap failed.") from exc
        if len(plaintext) != 32:
            raise KeyProviderError("Google Cloud KMS returned an invalid DEK length.")
        return plaintext

    def rewrap_dek(
        self,
        wrapped_dek: str,
        *,
        context: dict[str, str],
        kek_uri: str,
        kek_version: str,
    ) -> WrappedDek:
        plaintext = self.unwrap_dek(
            wrapped_dek,
            context=context,
            kek_uri=kek_uri,
            kek_version=kek_version,
        )
        try:
            return self._wrap(plaintext, context)
        finally:
            del plaintext
