"""Exercise registered practice/incident callbacks and session cleanup.

The API transport is replaced so these tests cover the actual Gradio input /
output wiring without running a server or executing any lab commands.
"""

from __future__ import annotations

import gradio as gr
import pytest

from src.app import gradio_ui


@pytest.fixture(scope="module")
def demo():
    return gradio_ui.build_ui()


@pytest.fixture(autouse=True)
def notices(monkeypatch):
    monkeypatch.setattr(gr, "Info", lambda *args, **kwargs: None)
    monkeypatch.setattr(gr, "Warning", lambda *args, **kwargs: None)


def _callback(demo, name):
    return next(item for item in demo.fns.values()
                if item.fn is not None and item.fn.__name__ == name)


def _fields(demo):
    return {component.elem_id: component for component in demo.blocks.values() if component.elem_id}


def _incident(**changes):
    data = {
        "id": "incident-1", "title": "Xác minh đăng nhập", "stage": "initial_access",
        "severity": "high", "status": "new", "version": 1, "evidence_count": 1,
        "resolution": None,
        "evidence": [{"audit_id": 12, "event_type": "auth.login.failed", "outcome": "failure",
                      "request_id": "request42", "created_at": "2026-09-30T10:20:00Z", "entry_hash": "abc123"}],
        "transitions": [{"from_status": None, "to_status": "new", "actor_id": "analyst42",
                         "created_at": "2026-09-30T10:22:00Z", "resolution": None}],
    }
    data.update(changes)
    return data


def _catalog():
    return {
        "stages": [{"id": "scanning", "title": "Quét", "scope": "Mạng lab", "scenario_ids": ["scan-probe"]}],
        "lessons": [{"id": "packet-lab", "title": "Bắt gói", "category": "Mạng", "stage": "scanning",
                     "objective": "Đối chiếu kết nối", "scope": "Máy lab",
                     "steps": ["Lọc DNS trong Wireshark"], "expected_evidence": ["Mốc thời gian"],
                     "questions": ["Có TCP handshake không?"], "completion": ["Đối chiếu với máy trạm"]}],
    }


def test_catalog_and_lesson_selection_use_authenticated_api(demo, monkeypatch):
    calls = []

    def api(*args, **kwargs):
        calls.append((args, kwargs))
        return _catalog()

    monkeypatch.setattr(gradio_ui, "_api", api)
    refresh = _callback(demo, "refresh_practice_catalog")
    result = refresh.fn("analyst-token")
    assert len(result) == len(refresh.outputs) == 3
    assert result[0]["choices"] == [("Mạng · Bắt gói", "packet-lab")]
    assert result[0]["value"] == "packet-lab"
    assert all(text in result[1] for text in ("Mục tiêu", "Các bước thực hiện", "Bằng chứng cần lưu", "Câu hỏi đối soát", "Điều kiện hoàn thành"))
    assert "Mạng lab" in result[2]
    selected = _callback(demo, "select_practice_lesson")
    assert selected.fn("analyst-token", "packet-lab") == result[1]
    assert calls == [(("analyst-token", "GET", "/api/admin/practice/catalog"), {})] * 2
    fields = _fields(demo)
    dependency = next(item for item in demo.config["dependencies"]
                      if (fields["practice-lesson"]._id, "input") in item["targets"])
    assert dependency["outputs"] == [fields["practice-guide"]._id]


def test_markdown_evidence_and_guides_keep_external_markup_inert():
    hostile = '<img src="https://outside.example/track"> ![pixel](https://outside.example/track)\n```html\n<script>alert(1)</script>\u202e'
    lesson = _catalog()["lessons"][0]
    lesson.update(title=hostile, steps=[hostile])
    guide = gradio_ui._practice_lesson_markdown(lesson)
    incident = _incident(title=hostile)
    incident["evidence"][0]["request_id"] = hostile
    detail = gradio_ui._incident_markdown(incident)
    for rendered in (guide, detail):
        assert "<img" not in rendered and "<script" not in rendered
        assert "![pixel](" not in rendered and "```html" not in rendered
        assert "&lt;img" in rendered and r"\!\[pixel\]\(" in rendered
        assert "\u202e" not in rendered
        assert r"\\u202E" in rendered


@pytest.mark.parametrize("role, visible", [("user", False), ("moderator", True), ("admin", True)])
def test_practice_tab_visibility_is_bound_to_authenticated_role(demo, monkeypatch, role, visible):
    def api(token, method, path, *args, **kwargs):
        assert token == "authenticated-token"
        if path == "/api/auth/me":
            return {"role": role, "username": "analyst", "mfa_enabled": True,
                    "ai_data_consent": False, "created_at": "2026-09-30T10:00:00Z"}
        assert path in ("/api/sessions", "/api/auth/sessions")
        return []

    monkeypatch.setattr(gradio_ui, "_api", api)
    practice_tab = next(item for item in demo.blocks.values()
                        if isinstance(item, gr.Tab) and item.label == "Thực hành ANM")
    assert practice_tab.visible is False
    workspace = _callback(demo, "load_workspace")
    values = dict(zip([item._id for item in workspace.outputs], workspace.fn("authenticated-token"), strict=True))
    assert values[practice_tab._id] == gr.update(visible=visible)


@pytest.mark.parametrize("reason", ["logout", "expiry"])
def test_session_end_clears_practice_data_and_revision(demo, monkeypatch, reason):
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **kwargs: {})
    monkeypatch.setattr(gradio_ui.time, "time", lambda: 1000)
    if reason == "logout":
        callback = _callback(demo, "do_logout")
        result = callback.fn("old-token")
    else:
        callback = _callback(demo, "tick")
        result = callback.fn(999, True)
    updates = dict(zip([item._id for item in callback.outputs], result, strict=True))
    fields = _fields(demo)
    for key in ("practice-guide", "practice-stages", "practice-incident-detail", "practice-incident-title", "practice-incident-evidence"):
        assert updates[fields[key]._id] == ""
    assert updates[fields["practice-incidents"]._id] == []
    for key in ("practice-lesson", "practice-incident"):
        assert updates[fields[key]._id] == gr.update(choices=[], value=None)
    update = _callback(demo, "update_incident")
    assert updates[update.inputs[2]._id] is None
    tab = next(item for item in demo.blocks.values() if isinstance(item, gr.Tab) and item.label == "Thực hành ANM")
    assert updates[tab._id] == gr.update(visible=False)
    assert updates[fields["practice-incident-status"]._id] == "investigating"
    assert updates[fields["practice-incident-resolution"]._id] == ""


def test_incident_refresh_clears_selection_and_loaded_revision(demo, monkeypatch):
    calls = []

    def api(*args, **kwargs):
        calls.append((args, kwargs))
        return [_incident()]

    monkeypatch.setattr(gradio_ui, "_api", api)
    callback = _callback(demo, "refresh_incidents")
    result = callback.fn("analyst-token")
    assert calls == [(("analyst-token", "GET", "/api/admin/incidents"), {"params": {"limit": "50"}})]
    assert result[0][0] == ["incident-1", "Xác minh đăng nhập", "initial_access", "high", "new", 1, 1]
    assert result[1]["value"] is None
    assert result[2:] == ("", None, "investigating", "")
    assert len(result) == len(callback.outputs)


def test_select_incident_renders_evidence_and_keeps_only_id_version_in_state(demo, monkeypatch):
    data = _incident()
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **kwargs: data)
    callback = _callback(demo, "select_incident")
    detail, revision, status, resolution = callback.fn("analyst-token", "incident-1")
    assert all(value in detail for value in ("Audit #12", "request42", "abc123", "analyst42", "Lịch sử xử lý"))
    assert revision == {"id": "incident-1", "version": 1}
    assert status == "investigating" and resolution == ""
    assert callback.fn("analyst-token", None) == ("", None, "investigating", "")


@pytest.mark.parametrize("raw", ["", "0", "-1", "1,1", "1,", "1;2", "1.5", "١", str(2**63), "9" * 5000, ",".join(str(i) for i in range(1, 22))])
def test_create_rejects_invalid_evidence_without_api_call(demo, monkeypatch, raw):
    calls = []
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **kwargs: calls.append(args))
    callback = _callback(demo, "create_incident")
    assert callback.fn("analyst-token", "Sự cố", "scanning", "medium", raw) == tuple(gr.skip() for _ in callback.outputs)
    assert calls == []


def test_create_incident_refreshes_list_and_shows_returned_detail(demo, monkeypatch):
    calls = []

    def api(token, method, path, body=None, **kwargs):
        calls.append((token, method, path, body, kwargs))
        return _incident() if method == "POST" else [_incident()]

    monkeypatch.setattr(gradio_ui, "_api", api)
    callback = _callback(demo, "create_incident")
    result = callback.fn("analyst-token", "  Sự cố đăng nhập  ", "initial_access", "high", "12, 13")
    assert calls[0] == ("analyst-token", "POST", "/api/admin/incidents", {
        "title": "Sự cố đăng nhập", "stage": "initial_access", "severity": "high", "evidence_ids": [12, 13],
    }, {})
    assert [call[1] for call in calls] == ["POST", "GET"]
    assert result[1]["value"] == "incident-1"
    assert result[3] == {"id": "incident-1", "version": 1}
    assert result[-2:] == ("", "")
    assert len(result) == len(callback.outputs) == 8


def test_conflict_submits_loaded_version_without_silent_reload(demo, monkeypatch):
    calls = []
    warnings = []

    def api(*args, **kwargs):
        calls.append((args, kwargs))
        raise gr.Error("HTTP 409: hồ sơ đã thay đổi")

    monkeypatch.setattr(gradio_ui, "_api", api)
    monkeypatch.setattr(gr, "Warning", lambda message, **kwargs: warnings.append(message))
    callback = _callback(demo, "update_incident")
    revision = {"id": "incident-1", "version": 1}
    result = callback.fn("analyst-token", "incident-1", revision, "contained", "")
    assert calls == [(("analyst-token", "PATCH", "/api/admin/incidents/incident-1", {
        "version": 1, "status": "contained", "resolution": None,
    }), {})]
    assert result == tuple(gr.skip() for _ in callback.outputs)
    assert revision == {"id": "incident-1", "version": 1}
    assert "409" in warnings[0]


def test_close_records_resolution_and_returned_revision(demo, monkeypatch):
    calls = []
    data = _incident(status="closed", version=3, resolution="confirmed")

    def api(token, method, path, body=None, **kwargs):
        calls.append((method, path, body))
        return data if method == "PATCH" else [data]

    monkeypatch.setattr(gradio_ui, "_api", api)
    callback = _callback(demo, "update_incident")
    result = callback.fn("analyst-token", "incident-1", {"id": "incident-1", "version": 2}, "closed", "confirmed")
    assert calls[0] == ("PATCH", "/api/admin/incidents/incident-1", {"version": 2, "status": "closed", "resolution": "confirmed"})
    assert result[3:] == ({"id": "incident-1", "version": 3}, "closed", "confirmed")
    assert len(result) == len(callback.outputs) == 6


@pytest.mark.parametrize("revision,status,resolution", [
    (None, "investigating", ""),
    ({"id": "other-incident", "version": 1}, "investigating", ""),
    ({"id": "incident-1", "version": 1}, "closed", ""),
    ({"id": "incident-1", "version": 1}, "contained", "confirmed"),
])
def test_update_requires_loaded_selection_and_consistent_resolution(demo, monkeypatch, revision, status, resolution):
    calls = []
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **kwargs: calls.append(args))
    callback = _callback(demo, "update_incident")
    result = callback.fn("analyst-token", "incident-1", revision, status, resolution)
    assert result == tuple(gr.skip() for _ in callback.outputs)
    assert calls == []


def test_practice_tab_select_refreshes_catalog_then_incidents(demo):
    tab = next(item for item in demo.blocks.values() if isinstance(item, gr.Tab) and item.label == "Thực hành ANM")
    event = next(item for item in demo.config["dependencies"] if (tab._id, "select") in item["targets"])
    assert demo.fns[event["id"]].fn.__name__ == "refresh_practice_catalog"
    chained = next(item for item in demo.config["dependencies"] if item["trigger_after"] == event["id"])
    assert demo.fns[chained["id"]].fn.__name__ == "refresh_incidents"
    markdown = "\n".join(str(item.value) for item in demo.blocks.values() if isinstance(item, gr.Markdown))
    assert "-m scripts.practice_lab --output-dir reports/practice-lab" in markdown
    assert "network-training.pcap" in markdown
    assert "Thu hồi phiên, khóa tài khoản" in markdown


def test_ui_callbacks_follow_real_incident_lifecycle(demo, client, app, monkeypatch):
    """Catch contract drift with the real sealed audit and incident service."""
    from src.app.models import User

    password = "Correct Horse Battery1"
    registered = client.post("/api/auth/register", json={"username": "practice-ui-real", "password": password})
    assert registered.status_code == 201, registered.text
    with app.state.database.session_factory() as session:
        session.get(User, registered.json()["id"]).role = "moderator"
        session.commit()
    login = client.post("/api/auth/login", json={"username": "practice-ui-real", "password": password})
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]

    def api(token, method, path, body=None, *, params=None):
        response = client.request(method, path, headers={"Authorization": f"Bearer {token}"},
                                  json=body, params=params)
        if response.status_code >= 400:
            raise gr.Error(str(response.json().get("detail")))
        return response.json()

    monkeypatch.setattr(gradio_ui, "_api", api)
    catalog = _callback(demo, "refresh_practice_catalog").fn(token)
    assert len(catalog[0]["choices"]) >= 5
    audit = api(token, "GET", "/api/admin/audit", params={"limit": "10"})
    create = _callback(demo, "create_incident")
    created = create.fn(token, "Đối soát phiên lab", "initial_access", "medium", str(audit[0]["id"]))
    assert created[3]["version"] == 1
    incident_id = created[3]["id"]
    revision = created[3]
    update = _callback(demo, "update_incident")
    for version, status, resolution in ((2, "investigating", ""), (3, "contained", ""), (4, "closed", "confirmed")):
        result = update.fn(token, incident_id, revision, status, resolution)
        assert result[3] == {"id": incident_id, "version": version}
        assert result[4:] == (status, resolution)
        revision = result[3]
    selected = _callback(demo, "select_incident").fn(token, incident_id)
    assert selected[1:] == (revision, "closed", "confirmed")
    detail = api(token, "GET", f"/api/admin/incidents/{incident_id}")
    assert len(detail["transitions"]) == 4
    assert detail["evidence"][0]["audit_id"] == audit[0]["id"]
