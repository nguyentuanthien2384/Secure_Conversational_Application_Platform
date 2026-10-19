"""Shared-VPS edge: SCAP's Caddy behind another app's front proxy.

Caddyfile.shared-proxy duplicates the public Caddyfile so the high-security and
direct VPS profiles stay untouched. These checks keep both files in lockstep
and make sure the deployment bundle ships every file Compose mounts.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _directives(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")]


def _public_site() -> list[str]:
    text = (ROOT / "Caddyfile").read_text(encoding="utf-8")
    body = text.split("{$PUBLIC_DOMAIN} {", 1)[1].split("http://{$PUBLIC_DOMAIN} {", 1)[0]
    return _directives(body)


def _shared_site() -> list[str]:
    text = (ROOT / "Caddyfile.shared-proxy").read_text(encoding="utf-8")
    return _directives(text.split("http://{$PUBLIC_DOMAIN} {", 1)[1])


def test_shared_proxy_site_keeps_every_public_rule():
    expected = _public_site()
    tls = expected.index("tls {")
    assert expected[tls:tls + 3] == ["tls {", "protocols tls1.3", "}"]
    del expected[tls:tls + 3]
    while "header_up X-Real-IP {remote_host}" in expected:
        real_ip = expected.index("header_up X-Real-IP {remote_host}")
        expected[real_ip:real_ip + 1] = ["header_up X-Forwarded-For {client_ip}",
                                         "header_up X-Real-IP {client_ip}"]
    assert _shared_site() == expected


def test_frontend_assets_queue_at_the_edge_below_per_ip_concurrency():
    # HTTP/2 lets one page load request ~110 Gradio files at once; the app
    # answers 503 above REQUEST_IP_MAX_CONCURRENT, which left the UI on "Loading...".
    from scripts.prepare_vps import _LIMITS

    for name in ("Caddyfile", "Caddyfile.shared-proxy"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assets = text.split("handle @frontend_assets {", 1)[1].split("\n\t}\n", 1)[0]
        assert "path /assets/* /static/*" in text
        bound = int(re.search(r"max_conns_per_host (\d+)", assets)[1])
        assert 1 <= bound < _LIMITS["REQUEST_IP_MAX_CONCURRENT"][0], name


def test_upstream_health_check_is_high_only_and_within_readiness_budget():
    # High: Caddy must stop routing while /api/ready is 503 (audit WORM down or
    # tail unanchored). Standard: readiness also sheds load, and one instance
    # marked unhealthy would be a full outage, so no active check there.
    from src.app.config import Settings

    import_line = "import app_health_{$CADDY_APP_HEALTH:none}"
    snippets = []
    for name in ("Caddyfile", "Caddyfile.shared-proxy"):
        text = (ROOT / name).read_text(encoding="utf-8")
        snippet = re.search(r"^\(app_health_ready\) \{\n(.*?)^\}\n", text, re.MULTILINE | re.DOTALL)
        assert snippet and re.search(r"^\(app_health_none\) \{\n\}\n", text, re.MULTILINE), name
        snippets.append(snippet[1])
        # One prober only (each import starts its own), on the app route.
        assert text.count(import_line) == 1, name
        assets = text.split("handle @frontend_assets {", 1)[1].split("\n\t}\n", 1)[0]
        assert import_line not in assets, name
    assert snippets[0] == snippets[1]
    probe = _directives(snippets[0])
    assert "health_uri /api/ready" in probe and "Host {$PUBLIC_DOMAIN}" in probe
    assert "health_status 200" in probe

    high = (ROOT / "docker-compose.high-security.yml").read_text(encoding="utf-8")
    caddy = high.split("\n  caddy:\n", 1)[1].split("\n  app:\n", 1)[0]
    assert "CADDY_APP_HEALTH: ready" in caddy
    for name in ("docker-compose.yml", "docker-compose.vps-demo.yml", "docker-compose.shared-proxy.yml"):
        assert "CADDY_APP_HEALTH" not in (ROOT / name).read_text(encoding="utf-8"), name

    # Edge probes plus the Docker healthcheck must not trip the readiness limiter.
    interval = int(re.search(r"health_interval (\d+)s", snippets[0])[1])
    docker_interval = int(re.search(
        r"HEALTHCHECK --interval=(\d+)s", (ROOT / "Dockerfile").read_text(encoding="utf-8")
    )[1])
    defaults = Settings()
    probes = defaults.request_window_seconds * (1 / interval + 1 / docker_interval)
    assert probes < defaults.readiness_max_attempts


def test_shared_proxy_trusts_only_the_front_proxy_address():
    text = (ROOT / "Caddyfile.shared-proxy").read_text(encoding="utf-8")
    options = _directives(text.split("http://{$PUBLIC_DOMAIN} {", 1)[0])
    assert "auto_https off" in options
    assert "trusted_proxies static {$SCAP_FRONT_PROXY_IPV4}/32" in options
    assert "trusted_proxies_strict" in options
    assert "private_ranges" not in text
    public_options = _directives((ROOT / "Caddyfile").read_text(encoding="utf-8").split("\n}\n", 1)[0])
    for option in ("read_header 10s", "read_body 60s", "idle 2m", "max_header_size 32KB"):
        assert option in public_options and option in options


def test_front_proxy_site_template_requires_tls13():
    template = _directives((ROOT / "deploy/shared-proxy-site.caddy").read_text(encoding="utf-8"))
    assert template[0] == "__PUBLIC_DOMAIN__ {"
    assert "protocols tls1.3" in template
    assert "reverse_proxy __SCAP_CADDY__:80 {" in template


def test_deploy_bundle_ships_every_bind_mount_and_script():
    script = (ROOT / "deploy/deploy.ps1").read_text(encoding="utf-8")

    def listed(name: str) -> list[str]:
        block = re.search(rf"\${name} = @\((.*?)\)", script, re.DOTALL)
        assert block, name
        return re.findall(r'"([^"]+)"', block[1])

    bundle, scripts = listed("BundleFiles"), listed("RemoteScripts")
    sources = set()
    for name in ("docker-compose.yml", "docker-compose.vps-demo.yml", "docker-compose.shared-proxy.yml"):
        compose = (ROOT / name).read_text(encoding="utf-8")
        sources.update(re.findall(r"^\s*- \./([^:\s]+):", compose, re.MULTILINE))
    assert sources >= {"Caddyfile", "Caddyfile.shared-proxy", "scripts/init_db_roles.sh"}
    for source in sources:
        assert any(source == item or source.startswith(item + "/") for item in bundle), source
    for item in [*bundle, *scripts, "deploy/vps.env.example"]:
        assert (ROOT / item).exists(), item
    # Files executed or mounted on Linux must keep LF line endings.
    for item in [*scripts, "Caddyfile.shared-proxy", "docker-compose.shared-proxy.yml",
                 "deploy/shared-proxy-site.caddy", "deploy/server-setup.sh", "deploy/update.sh"]:
        assert b"\r" not in (ROOT / item).read_bytes(), item
