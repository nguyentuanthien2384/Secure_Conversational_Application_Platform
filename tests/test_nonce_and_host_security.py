from __future__ import annotations

import json
import re
from dataclasses import replace
from types import SimpleNamespace

import gradio.routes
import pytest
from fastapi.testclient import TestClient
from starlette.routing import Mount

from src.app.config import Settings
from src.app.gradio_csp import _Scripts, _trusted_template, _validate_custom_scripts
from src.app.host_security import effective_allowed_hosts, normalize_allowed_hosts
from src.app.main import create_app


def _page_scripts(response):
    parser = _Scripts()
    parser.feed(response.text)
    return parser.scripts


def test_real_gradio_homepage_has_fresh_matching_nonces(client):
    vendor_loader = gradio.routes.templates.env.loader
    first, second = client.get("/"), client.get("/")
    assert first.status_code == second.status_code == 200
    nonces = []
    for response in (first, second):
        csp = response.headers["content-security-policy"]
        script_policy = next(part.strip() for part in csp.split(";") if part.strip().startswith("script-src "))
        assert "unsafe-inline" not in script_policy and "unsafe-eval" not in script_policy
        assert "script-src-attr 'none'" in csp
        assert "style-src 'self' 'unsafe-inline'" in csp
        nonce = re.search(r"'nonce-([A-Za-z0-9_-]{32})'", script_policy).group(1)
        scripts = _page_scripts(response)
        assert len(scripts) == 6
        assert all(attrs["nonce"] == nonce for attrs, _ in scripts)
        assert len([attrs for attrs, _ in scripts if "src" not in attrs]) == 4
        assert response.headers["cache-control"] == "no-store"
        nonces.append(nonce)
    assert nonces[0] != nonces[1]
    assert gradio.routes.templates.env.loader is vendor_loader


def test_hostile_bootstrap_values_cannot_create_a_nonced_script(app):
    mounted = next(route.app for route in app.routes if isinstance(route, Mount))
    blocks = mounted.get_blocks()
    payload = '</script><script nonce="attacker">window.attack=true</script>'
    blocks.config["title"] = payload
    blocks.config["components"][0]["props"]["value"] = payload
    with TestClient(app) as client:
        response = client.get("/")
    assert response.status_code == 200
    scripts = _page_scripts(response)
    assert len(scripts) == 6
    config_script = next(body for _, body in scripts if body.startswith("window.gradio_config = "))
    config = json.loads(config_script.removeprefix("window.gradio_config = ").removesuffix(";"))
    assert config["title"] == payload
    assert config["components"][0]["props"]["value"] == payload
    assert "</script>" not in config_script and 'nonce="attacker"' not in response.text


@pytest.mark.parametrize("mutation", [
    lambda source: source.replace("</head>", "<script>alert(1)</script></head>"),
    lambda source: source.replace("window.__gradio_mode__ = \"app\";", "window.attack = true;"),
    lambda source: source.replace("./assets/index-", "https://evil.example/index-"),
])
def test_unrecognized_vendor_bootstrap_fails_closed(mutation):
    vendor = gradio.routes.templates
    source, _, _ = vendor.env.loader.get_source(vendor.env, "frontend/index.html")
    with pytest.raises(RuntimeError, match="incompatible"):
        _trusted_template(mutation(source))


@pytest.mark.parametrize("js,head,share", [
    ("alert(1)", "", False),
    (None, '<script src="https://evil.example/code.js"></script>', False),
    (None, '<script>alert(1)</script>', False),
    (None, "", True),
])
def test_custom_script_surfaces_fail_closed(js, head, share):
    with pytest.raises(RuntimeError):
        _validate_custom_scripts(SimpleNamespace(share=share, config={"js": js, "head": head}))


def test_application_owned_template_environments_are_isolated(settings):
    first, second = create_app(settings), create_app(settings)
    with TestClient(first) as one, TestClient(second) as two:
        a, b = one.get("/"), two.get("/")
    nonce_a = _page_scripts(a)[0][0]["nonce"]
    nonce_b = _page_scripts(b)[0][0]["nonce"]
    assert nonce_a != nonce_b
    assert nonce_a not in b.text and nonce_b not in a.text


def test_local_defaults_block_dns_rebinding_even_with_matching_origin(settings):
    application = create_app(replace(settings, environment="development"))
    with TestClient(application, base_url="http://127.0.0.1:8000") as client:
        assert client.get("/api/health").status_code == 200
        for host in ("evil.example", "localhost.evil.example", "2130706433", "127.0.0.1.evil.example"):
            response = client.get("/api/health", headers={"Host": host})
            assert response.status_code == 400
            assert response.headers["cache-control"] == "no-store"
            assert client.post("/api/sessions", headers={
                "Host": host, "Origin": f"http://{host}", "Sec-Fetch-Site": "same-origin",
            }, json={"title": "must never reach auth"}).status_code == 400


@pytest.mark.parametrize("host", ["localhost", "LOCALHOST:8000", "127.0.0.1:8000", "[::1]:8000", "[0:0:0:0:0:0:0:1]"])
def test_exact_local_hosts_support_ipv6_and_valid_ports(settings, host):
    with TestClient(create_app(replace(settings, environment="development")), base_url="http://localhost") as client:
        assert client.get("/api/health", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize("host", [
    "[::2]:8000", "::1", "[::1]:", "[::1]:65536", "localhost:", "localhost:0",
    "localhost:8000.evil.example", "localhost,evil.example", "localhost@evil.example",
    "localhost.", "localhost:abc", "[::1%lo]", "localhost:80:80", " localhost", "",
])
def test_malformed_or_unallowlisted_host_never_reaches_application(client, host):
    assert client.get("/api/health", headers={"Host": host}).status_code == 400


def test_explicit_lan_or_domain_hosts_are_exact(settings):
    custom = replace(settings, allowed_hosts=("192.168.1.7", "CHAT.example"))
    with TestClient(create_app(custom), base_url="https://chat.example") as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/health", headers={"Host": "192.168.1.7:8000"}).status_code == 200
        assert client.get("/api/health", headers={"Host": "evil.chat.example"}).status_code == 400
        assert client.get("/api/health", headers={"Host": "127.0.0.1"}).status_code == 400


@pytest.mark.parametrize("host", ["*", "*.example.com", "https://chat.example", "chat.example:443", "chat.example/", "host with space"])
def test_host_configuration_rejects_permissive_or_ambiguous_values(host):
    with pytest.raises(ValueError, match="ALLOWED_HOSTS"):
        normalize_allowed_hosts((host,))


def test_production_cannot_omit_host_policy(settings):
    with pytest.raises(ValueError, match="ALLOWED_HOSTS"):
        create_app(replace(settings, environment="production", allowed_hosts=()))
    assert effective_allowed_hosts((), "test") == ("127.0.0.1", "localhost", "::1", "testserver")
    assert effective_allowed_hosts((), "development") == ("127.0.0.1", "localhost", "::1")


def test_from_env_defaults_local_and_rejects_wildcards(monkeypatch):
    monkeypatch.setattr("src.app.config.load_dotenv", lambda: None)
    monkeypatch.setattr("src.app.config.os.environ", {})
    assert Settings.from_env().allowed_hosts == ("127.0.0.1", "localhost", "::1")
    monkeypatch.setenv("ALLOWED_HOSTS", "*.example.com")
    with pytest.raises(RuntimeError, match="wildcards"):
        Settings.from_env()
