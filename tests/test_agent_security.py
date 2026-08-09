from __future__ import annotations

import ast
from pathlib import Path

from sqlalchemy import select, text

from src.app.models import AuditEvent


def _headers(client) -> dict[str, str]:
    registration = client.post(
        "/api/auth/register",
        json={"username": "agent.user", "password": "Correct Horse Battery1"},
    )
    assert registration.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"username": "agent.user", "password": "Correct Horse Battery1"},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _run(client, headers, scopes: list[str], tool: str, arguments: dict):
    response = client.post(
        "/api/agent/runs",
        headers=headers,
        json={
            "approved_scopes": scopes,
            "tool_calls": [{"tool": tool, "arguments": arguments}],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_agent_exposes_only_signed_allowlisted_manifests(client):
    response = client.get("/api/agent/tools", headers=_headers(client))
    assert response.status_code == 200
    manifests = response.json()
    assert {item["name"] for item in manifests} == {
        "workspace.list",
        "workspace.read",
        "workspace.write",
        "repo.search",
        "egress.inspect",
        "sandbox.execute",
    }
    assert all(item["version"] == "builtin@1" for item in manifests)
    assert len({item["manifest_signature"] for item in manifests}) == 1


def test_agent_requires_explicit_capability_for_workspace_write(client, settings):
    headers = _headers(client)
    denied = _run(
        client,
        headers,
        ["workspace:read"],
        "workspace.write",
        {"path": "notes.txt", "content": "must not be written"},
    )
    assert denied["status"] == "completed_with_denials"
    assert denied["results"][0]["status"] == "denied"
    assert not list(Path(settings.agent_workspace_root).rglob("notes.txt"))


def test_agent_workspace_blocks_traversal_and_keeps_arguments_out_of_audit(client, app):
    headers = _headers(client)
    secret_content = "api_key=never-log-this-agent-tool-input"
    write = _run(
        client,
        headers,
        ["workspace:write"],
        "workspace.write",
        {"path": "memo.txt", "content": secret_content},
    )
    assert write["results"][0]["status"] == "success"

    traversal = _run(
        client,
        headers,
        ["workspace:read"],
        "workspace.read",
        {"path": "../../.env"},
    )
    assert traversal["results"][0]["status"] == "denied"
    assert "workspace" in traversal["results"][0]["detail"].lower()

    with app.state.database.session_factory() as db:
        events = db.scalars(select(AuditEvent).where(AuditEvent.event_type == "agent.run")).all()
    assert events
    assert all(secret_content not in event.details_json for event in events)
    assert all("memo.txt" not in event.details_json for event in events)


def test_agent_egress_and_sandbox_are_deny_by_default(client):
    headers = _headers(client)
    private_destination = _run(
        client,
        headers,
        ["egress:inspect"],
        "egress.inspect",
        {"url": "https://127.0.0.1/private"},
    )
    assert private_destination["results"][0]["status"] == "denied"
    assert "SSRF" in private_destination["results"][0]["detail"]

    sandbox = _run(
        client,
        headers,
        ["sandbox:execute"],
        "sandbox.execute",
        {"language": "python", "code": "print('not executed')"},
    )
    assert sandbox["results"][0]["status"] == "denied"
    assert "không bao giờ chạy lệnh" in sandbox["results"][0]["detail"]


def test_agent_module_has_no_subprocess_or_http_client_escape_hatch():
    source = Path(__file__).resolve().parents[1] / "src" / "app" / "agent.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    imported_modules = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_modules.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert "subprocess" not in imported_modules
    assert "httpx" not in imported_modules
    assert "requests" not in imported_modules


def test_agent_rejects_unknown_scope_before_execution(client):
    response = client.post(
        "/api/agent/runs",
        headers=_headers(client),
        json={
            "approved_scopes": ["host:root"],
            "tool_calls": [{"tool": "workspace.list", "arguments": {}}],
        },
    )
    assert response.status_code == 422
    assert "capability" in response.json()["detail"].lower()


def test_agent_retrieval_is_encrypted_and_tenant_scoped(client, app):
    owner = _headers(client)
    private_text = "Project Aurora must never appear in another tenant search."
    created = client.post(
        "/api/agent/documents",
        headers=owner,
        json={"title": "private-note", "content": private_text},
    )
    assert created.status_code == 201, created.text
    own_search = client.post("/api/agent/retrieval/search", headers=owner, json={"query": "Aurora"})
    assert own_search.status_code == 200
    assert own_search.json()[0]["document_id"] == created.json()["id"]

    other_registration = client.post(
        "/api/auth/register", json={"username": "other.tenant", "password": "Correct Horse Battery1"}
    )
    assert other_registration.status_code == 201
    other_login = client.post(
        "/api/auth/login", json={"username": "other.tenant", "password": "Correct Horse Battery1"}
    )
    other_headers = {"Authorization": f"Bearer {other_login.json()['access_token']}"}
    other_search = client.post(
        "/api/agent/retrieval/search", headers=other_headers, json={"query": "Aurora"}
    )
    assert other_search.status_code == 200
    assert other_search.json() == []

    with app.state.database.session_factory() as db:
        document_row = db.execute(text("SELECT ciphertext FROM agent_documents")).scalar_one()
    assert private_text not in document_row
