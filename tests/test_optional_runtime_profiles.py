"""Cloud profiles exercise their installed SDKs without credentials or network."""
from __future__ import annotations

import base64
import secrets

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.app.key_management import (
    AwsKmsKeyProvider,
    GcpKmsKeyProvider,
    KeyProvider,
    KeyProviderError,
    canonical_context,
)
from tests.test_vps_compose import DOCKER, resolved_compose

CONTEXT = {"owner_id": "offline-owner", "session_id": "offline-session", "epoch": "1"}
AWS_KEY = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
GCP_KEY = "projects/offline/locations/global/keyRings/scap/cryptoKeys/conversations"


@pytest.fixture
def aws_sdk(monkeypatch):
    boto3 = pytest.importorskip("boto3", reason="AWS runtime extra is not installed")
    from botocore.stub import Stubber

    # Explicit synthetic credentials suppress the entire SDK credential chain,
    # including metadata services. Stubber intercepts every service operation.
    client = boto3.session.Session(
        aws_access_key_id="offline-test", aws_secret_access_key="offline-test",
    ).client("kms", region_name="us-east-1")

    def sdk_client(service, *, region_name):
        assert (service, region_name) == ("kms", "us-east-1")
        return client

    monkeypatch.setattr(boto3, "client", sdk_client)
    with Stubber(client) as stub:
        yield AwsKmsKeyProvider(key_id=AWS_KEY, region="us-east-1"), stub
        stub.assert_no_pending_responses()
    client.close()


def test_aws_sdk_data_key_metadata_and_rewrap_round_trip(aws_sdk):
    provider, stub = aws_sdk
    plaintext, original, rotated = b"D" * 32, b"original wrapped cloud key", b"rotated wrapped cloud key"
    sdk_context = {"scap-format": "v1", **CONTEXT}
    stub.add_response("generate_data_key", {
        "Plaintext": plaintext, "CiphertextBlob": original, "KeyId": AWS_KEY,
    }, {"KeyId": AWS_KEY, "KeySpec": "AES_256", "EncryptionContext": sdk_context})
    stub.add_response("decrypt", {"Plaintext": plaintext, "KeyId": AWS_KEY}, {
        "KeyId": AWS_KEY, "CiphertextBlob": original, "EncryptionContext": sdk_context,
    })
    stub.add_response("re_encrypt", {"CiphertextBlob": rotated, "KeyId": AWS_KEY}, {
        "CiphertextBlob": original, "SourceEncryptionContext": sdk_context,
        "DestinationKeyId": AWS_KEY, "DestinationEncryptionContext": sdk_context,
    })
    stub.add_response("decrypt", {"Plaintext": plaintext, "KeyId": AWS_KEY}, {
        "KeyId": AWS_KEY, "CiphertextBlob": rotated, "EncryptionContext": sdk_context,
    })
    generated = provider.generate_wrapped_dek(context=CONTEXT)
    assert isinstance(provider, KeyProvider)
    assert generated.plaintext_dek == plaintext
    assert isinstance(generated.plaintext_dek, bytes)
    assert base64.urlsafe_b64decode(generated.wrapped_dek) == original
    assert generated.kek_uri == provider.kek_uri == f"aws-kms://us-east-1/{AWS_KEY}"
    assert generated.kek_version == AWS_KEY
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(generated.plaintext_dek).encrypt(nonce, b"private demo message", b"message-aad")
    unwrapped = provider.unwrap_dek(generated.wrapped_dek, context=CONTEXT,
                                    kek_uri=generated.kek_uri, kek_version=generated.kek_version)
    assert AESGCM(unwrapped).decrypt(nonce, ciphertext, b"message-aad") == b"private demo message"
    rewrapped = provider.rewrap_dek(generated.wrapped_dek, context=CONTEXT,
                                    kek_uri=generated.kek_uri, kek_version=generated.kek_version)
    assert base64.urlsafe_b64decode(rewrapped.wrapped_dek) == rotated
    assert rewrapped.kek_uri == generated.kek_uri and rewrapped.kek_version == AWS_KEY
    recovered = provider.unwrap_dek(rewrapped.wrapped_dek, context=CONTEXT,
                                    kek_uri=rewrapped.kek_uri, kek_version=rewrapped.kek_version)
    assert recovered == plaintext


@pytest.mark.parametrize("operation", ["generate", "unwrap", "rewrap"])
def test_aws_sdk_failure_is_closed_and_does_not_expose_service_details(aws_sdk, operation):
    provider, stub = aws_sdk
    method = {"generate": "generate_data_key", "unwrap": "decrypt", "rewrap": "re_encrypt"}[operation]
    stub.add_client_error(method, service_error_code="AccessDeniedException",
                          service_message="private-provider-detail", http_status_code=403)
    with pytest.raises(KeyProviderError) as captured:
        if operation == "generate":
            provider.generate_wrapped_dek(context=CONTEXT)
        else:
            getattr(provider, f"{operation}_dek")(
                base64.urlsafe_b64encode(b"wrapped").decode(), context=CONTEXT,
                kek_uri=provider.kek_uri, kek_version=AWS_KEY,
            )
    assert "private-provider-detail" not in str(captured.value)


@pytest.mark.parametrize("operation", ["generate", "unwrap"])
def test_aws_sdk_rejects_non_aes256_data_keys(aws_sdk, operation):
    provider, stub = aws_sdk
    method = "generate_data_key" if operation == "generate" else "decrypt"
    response = {"Plaintext": b"short-key", "KeyId": AWS_KEY}
    if operation == "generate":
        response["CiphertextBlob"] = b"wrapped"
    stub.add_response(method, response)
    with pytest.raises(KeyProviderError, match="invalid DEK length"):
        if operation == "generate":
            provider.generate_wrapped_dek(context=CONTEXT)
        else:
            provider.unwrap_dek(base64.urlsafe_b64encode(b"wrapped").decode(), context=CONTEXT,
                                kek_uri=provider.kek_uri, kek_version=AWS_KEY)


def test_aws_sdk_rejects_wrong_key_uri_before_service_call(aws_sdk):
    provider, _stub = aws_sdk
    for method in (provider.unwrap_dek, provider.rewrap_dek):
        with pytest.raises(KeyProviderError, match="URI does not match"):
            method("unused", context=CONTEXT, kek_uri="aws-kms://other/key", kek_version=AWS_KEY)


@pytest.fixture
def gcp_sdk(monkeypatch):
    kms = pytest.importorskip("google.cloud.kms", reason="GCP runtime extra is not installed")
    from google.auth.credentials import AnonymousCredentials

    # Exercise the actual SDK client/protobuf request conversion. Replace its
    # final wrapped transport functions before constructing our adapter; no
    # HTTP/RPC operation or ADC credential lookup can occur.
    client = kms.KeyManagementServiceClient(credentials=AnonymousCredentials(), transport="rest")
    calls, mode = [], {"error": False, "short": False}
    cloud_key = AESGCM(b"C" * 32)

    def encrypt(request, **_options):
        assert isinstance(request, kms.EncryptRequest) and request.name == GCP_KEY
        calls.append(("encrypt", request.additional_authenticated_data))
        if mode["error"]:
            raise PermissionError("private-provider-detail")
        nonce = secrets.token_bytes(12)
        return kms.EncryptResponse(ciphertext=nonce + cloud_key.encrypt(
            nonce, request.plaintext, request.additional_authenticated_data,
        ))

    def decrypt(request, **_options):
        assert isinstance(request, kms.DecryptRequest) and request.name == GCP_KEY
        calls.append(("decrypt", request.additional_authenticated_data))
        if mode["error"]:
            raise PermissionError("private-provider-detail")
        plaintext = cloud_key.decrypt(request.ciphertext[:12], request.ciphertext[12:],
                                      request.additional_authenticated_data)
        return kms.DecryptResponse(plaintext=b"short-key" if mode["short"] else plaintext)

    client.transport._wrapped_methods[client.transport.encrypt] = encrypt
    client.transport._wrapped_methods[client.transport.decrypt] = decrypt
    monkeypatch.setattr(kms, "KeyManagementServiceClient", lambda: client)
    try:
        yield GcpKmsKeyProvider(key_name=GCP_KEY), mode, calls
    finally:
        client.transport.close()


def test_gcp_sdk_data_key_metadata_context_and_rewrap_round_trip(gcp_sdk):
    provider, _mode, calls = gcp_sdk
    generated = provider.generate_wrapped_dek(context=CONTEXT)
    assert isinstance(provider, KeyProvider)
    assert isinstance(generated.plaintext_dek, bytes) and len(generated.plaintext_dek) == 32
    assert isinstance(generated.wrapped_dek, str) and len(base64.urlsafe_b64decode(generated.wrapped_dek)) > 32
    assert generated.kek_uri == provider.kek_uri == f"gcp-kms://{GCP_KEY}"
    assert generated.kek_version == "current"
    original = provider.unwrap_dek(generated.wrapped_dek, context=CONTEXT,
                                  kek_uri=generated.kek_uri, kek_version=generated.kek_version)
    assert original == generated.plaintext_dek
    rotated = provider.rewrap_dek(generated.wrapped_dek, context=CONTEXT,
                                 kek_uri=generated.kek_uri, kek_version=generated.kek_version)
    assert rotated.wrapped_dek != generated.wrapped_dek and rotated.kek_uri == generated.kek_uri
    assert provider.unwrap_dek(rotated.wrapped_dek, context=CONTEXT,
                               kek_uri=rotated.kek_uri, kek_version=rotated.kek_version) == original
    assert [operation for operation, _context in calls] == ["encrypt", "decrypt", "decrypt", "encrypt", "decrypt"]
    assert all(context == canonical_context(CONTEXT) for _operation, context in calls)
    with pytest.raises(KeyProviderError, match="unwrap failed"):
        provider.unwrap_dek(rotated.wrapped_dek, context={**CONTEXT, "owner_id": "different-owner"},
                            kek_uri=rotated.kek_uri, kek_version=rotated.kek_version)


@pytest.mark.parametrize("operation", ["generate", "unwrap", "rewrap"])
def test_gcp_sdk_failure_is_closed_and_does_not_expose_service_details(gcp_sdk, operation):
    provider, mode, _calls = gcp_sdk
    generated = provider.generate_wrapped_dek(context=CONTEXT)
    mode["error"] = True
    with pytest.raises(KeyProviderError) as captured:
        if operation == "generate":
            provider.generate_wrapped_dek(context=CONTEXT)
        else:
            getattr(provider, f"{operation}_dek")(generated.wrapped_dek, context=CONTEXT,
                                                 kek_uri=generated.kek_uri, kek_version=generated.kek_version)
    assert "private-provider-detail" not in str(captured.value)


def test_gcp_sdk_rejects_short_dek_and_mismatched_uri(gcp_sdk):
    provider, mode, calls = gcp_sdk
    generated = provider.generate_wrapped_dek(context=CONTEXT)
    mode["short"] = True
    with pytest.raises(KeyProviderError, match="invalid DEK length"):
        provider.unwrap_dek(generated.wrapped_dek, context=CONTEXT,
                            kek_uri=generated.kek_uri, kek_version=generated.kek_version)
    previous = len(calls)
    for method in (provider.unwrap_dek, provider.rewrap_dek):
        with pytest.raises(KeyProviderError, match="URI does not match"):
            method(generated.wrapped_dek, context=CONTEXT,
                   kek_uri="gcp-kms://other/key", kek_version="current")
    assert len(calls) == previous


@pytest.mark.skipif(DOCKER is None, reason="Docker Compose CLI is unavailable")
@pytest.mark.parametrize("profile", ["local", "vault", "aws-kms", "gcp-kms"])
def test_app_and_migration_inherit_the_selected_runtime_build_profile(tmp_path, profile):
    # Compose config merges files only; it starts no containers or services.
    services = resolved_compose(tmp_path, overlay="local", overrides={"KEY_PROVIDER": profile})["services"]
    assert services["app"]["build"]["args"]["KMS_PROFILE"] == profile
    assert services["migrate"]["build"]["args"]["KMS_PROFILE"] == profile
