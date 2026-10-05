from __future__ import annotations

import json
import re

import pytest

from src.app.gradio_boundary import GradioBoundaryMiddleware


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.parametrize("path", [
    "/gradio_api/deep_link?session_hash=private-state",
    "/gradio_api/deep_link/?session_hash=private-state",
    "/gradio_api/%64eep_link?session_hash=private-state",
    "/gradio_api/%2564eep_link?session_hash=private-state",
    "/?deep_link=private-state", "/?%64eep_link=private-state",
    "/config?deep_link=private-state", "/?deep_link=",
])
def test_state_sharing_denied_before_gradio_state_access(client, app, path, monkeypatch):
    def unexpected_access(*args, **kwargs):
        raise AssertionError("vendor state snapshot handler must not run")

    monkeypatch.setattr("gradio.route_utils.create_url_safe_hash", unexpected_access)
    response = client.get(path)
    assert response.status_code == 404
    assert response.json() == {"detail": "UI state sharing is not available."}
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("headers", [
    {"X-Forwarded-Host": "evil.example"},
    {"X-Gradio-Server": "https://evil.example"},
    {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "evil.example"},
    {"Forwarded": "host=evil.example;proto=https", "X-Forwarded-Port": "443"},
])
def test_vendor_bootstrap_uses_validated_host_and_scope(client, headers):
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    match = re.search(r"window\.gradio_config\s*=\s*(\{.*?\});", response.text, re.DOTALL)
    assert match is not None
    config = json.loads(match.group(1))
    assert config["root"] == "http://testserver"
    assert "evil.example" not in response.text


@pytest.mark.anyio
async def test_boundary_preserves_trusted_asgi_scheme_client_and_root_path():
    captured = {}

    async def downstream(scope, receive, send):
        captured.update(scope)

    boundary = GradioBoundaryMiddleware(downstream)
    scope = {
        "type": "http", "path": "/", "query_string": b"", "scheme": "https",
        "client": ("203.0.113.8", 443), "root_path": "/scap",
        "headers": [(b"host", b"scap.example"), (b"x-forwarded-proto", b"http"),
                    (b"x-forwarded-host", b"evil.example"),
                    (b"x-auth-request-user", b"trusted-operator")],
    }

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        pass

    await boundary(scope, receive, send)
    assert captured["scheme"] == "https"
    assert captured["client"] == ("203.0.113.8", 443)
    assert captured["root_path"] == "/scap"
    assert captured["headers"] == [(b"host", b"scap.example"),
                                   (b"x-auth-request-user", b"trusted-operator")]
    assert len(scope["headers"]) == 4  # The caller's scope is not mutated.


def test_raw_origin_override_still_counts_toward_header_size_limit(client):
    response = client.get("/", headers={"X-Forwarded-Host": "x" * 33_000})
    assert response.status_code == 431


def test_report_policy_keeps_supported_styles_and_rejects_inline_scripts(client):
    response = client.get("/")
    report = response.headers["Content-Security-Policy-Report-Only"]
    assert "style-src 'self' 'unsafe-inline'" in report
    script_policy = next(part for part in report.split(";") if part.strip().startswith("script-src "))
    assert "'unsafe-inline'" not in script_policy
    assert "'unsafe-eval'" not in script_policy
    assert "'nonce-" in script_policy
