"""Verify the local crypto controls stay outside Gradio's data boundary."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import threading
from html.parser import HTMLParser
from pathlib import Path

import gradio as gr
import pytest
from gradio.state_holder import SessionState
from starlette.routing import Mount

from src.app import gradio_ui
from src.app.crypto_workbench_ui import WORKBENCH_HTML
from src.app.gradio_csp import _HEAD_ASSETS, _Scripts
from tests.conftest import register_and_login
from tests.test_ui_feature_completion import callback

ASSET_DIRECTORY = Path(__file__).resolve().parents[1] / "src" / "app" / "ui_assets"
ASSETS = ("crypto-workbench-core.js", "crypto-workbench.js")


def bridge_payload(markup):
    match = re.fullmatch(
        r'<span data-scap-cipher-extract="([^"]+)" '
        r'data-scap-cipher-nonce="([0-9a-f]{16})"></span>', markup,
    )
    assert match is not None
    return json.loads(base64.b64decode(match.group(1)).decode("utf-8"))


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text.append(data)


@pytest.fixture()
def demo(app):
    """Inspect the actual UI mounted by create_app, including its hardening."""
    return next(route.app.get_blocks() for route in app.routes if isinstance(route, Mount))


@pytest.fixture(autouse=True)
def quiet_notices(monkeypatch):
    monkeypatch.setattr(gr, "Info", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(gr, "Warning", lambda *_args, **_kwargs: None)


def test_private_workbench_fields_are_native_controls_without_gradio_dependencies(demo):
    workbench = next(component for component in demo.blocks.values()
                     if component.elem_id == "crypto-workbench")
    assert isinstance(workbench, gr.Markdown)
    assert workbench.sanitize_html is False
    assert workbench.value == WORKBENCH_HTML.strip()
    parser = Elements()
    parser.feed(workbench.value)
    fields = {attrs["data-crypto-field"]: (tag, attrs) for tag, attrs in parser.elements
              if "data-crypto-field" in attrs}
    assert {"passphrase", "confirm", "private-file", "source-message", "plaintext", "packet", "decrypted",
            "file-input", "file-context", "file-info", "file-result"} <= fields.keys()
    assert fields["source-message"][0] == "select"
    assert fields["passphrase"][1]["type"] == fields["confirm"][1]["type"] == "password"
    assert fields["private-file"][1]["type"] == "file"
    assert fields["decrypted"][1].get("readonly") is None
    assert "readonly" in fields["decrypted"][1]
    assert not any(tag in {"script", "iframe", "form", "object", "embed", "img"}
                   for tag, _attrs in parser.elements)
    for tag, attrs in parser.elements:
        assert not any(name.lower().startswith("on") for name in attrs)
        assert not any(name in attrs for name in ("action", "formaction", "src", "name"))
        if tag == "button":
            assert attrs["type"] == "button"
        if tag in {"input", "textarea", "select"}:
            assert attrs["id"].startswith("cw-")
            assert not any(component.elem_id == attrs["id"] for component in demo.blocks.values())
    for fn in demo.fns.values():
        assert workbench not in fn.inputs and workbench not in fn.outputs


def test_binary_file_controls_cannot_upload_files_through_gradio_or_submit_a_form(demo):
    parser = Elements()
    parser.feed(WORKBENCH_HTML)
    fields = {attrs["data-crypto-field"]: (tag, attrs) for tag, attrs in parser.elements
              if "data-crypto-field" in attrs}
    file_tag, file_attrs = fields["file-input"]
    assert file_tag == "input" and file_attrs["type"] == "file"
    assert "multiple" not in file_attrs
    context_tag, context_attrs = fields["file-context"]
    assert context_tag == "input" and context_attrs["type"] == "text"
    assert context_attrs["maxlength"] == "256"
    assert context_attrs["autocomplete"] == "off"
    for name in ("file-info", "file-result"):
        assert fields[name][0] not in {"input", "textarea", "iframe", "object", "embed"}
    for name in ("file-input", "file-context"):
        native_id = fields[name][1]["id"]
        assert not any(component.elem_id == native_id for component in demo.blocks.values())
    actions = {attrs["data-crypto-action"]: (tag, attrs) for tag, attrs in parser.elements
               if "data-crypto-action" in attrs}
    for action in ("encrypt-file", "decrypt-file"):
        tag, attrs = actions[action]
        assert tag == "button" and attrs["type"] == "button"
        assert "formaction" not in attrs
    # The workbench deliberately has no browser upload endpoint or submit form.
    assert not any(tag == "form" or "name" in attrs or "formaction" in attrs
                   for tag, attrs in parser.elements)


def test_file_profile_is_fixed_authenticated_encryption_without_raw_aes_key_controls():
    parser = Elements()
    parser.feed(WORKBENCH_HTML)
    profiles = [attrs for tag, attrs in parser.elements
                if tag == "dl" and attrs.get("data-crypto-file-profile") == "1"]
    assert len(profiles) == 1
    profile_match = re.search(r'<dl\b[^>]*data-crypto-file-profile="1"[^>]*>(.*?)</dl>',
                              WORKBENCH_HTML, flags=re.DOTALL)
    assert profile_match is not None
    profile = Elements()
    profile.feed(profile_match[1])
    profile_text = " ".join(" ".join(profile.text).split())
    assert "AES-256-GCM / 256 bit" in profile_text
    assert "96 bit / 128 bit" in profile_text
    assert "Không dùng (GCM)" in profile_text
    assert "RSA-OAEP 3072 / SHA-256" in profile_text
    assert not any(tag in {"input", "textarea", "select", "option", "button"}
                   for tag, _attrs in profile.elements)
    selectors = [attrs for tag, attrs in parser.elements if tag == "select"]
    assert selectors == [{"id": "cw-source-message", "data-crypto-field": "source-message"}]
    assert not any(re.search(r"(?:raw|aes|symmetric)[-_]?key", attrs.get("data-crypto-field", ""))
                   for _tag, attrs in parser.elements)
    text = " ".join(" ".join(parser.text).split())
    assert "5 MiB (5.242.880 byte)" in text


@pytest.mark.parametrize("asset", ASSETS)
def test_workbench_javascript_is_served_exactly_as_packaged_without_cache(client, asset):
    response = client.get(f"/api/ui-session/{asset}")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/javascript")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    packaged = (ASSET_DIRECTORY / asset.replace("-", "_")).read_text(encoding="utf-8")
    assert response.text == packaged
    assert not re.search(r"\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\s*\(", response.text)
    assert not re.search(r"\b(?:localStorage|sessionStorage|indexedDB)\b", response.text)
    assert not re.search(r"\b(?:eval|Function)\s*\(", response.text)
    assert "innerHTML" not in response.text and "document.cookie" not in response.text


def test_real_gradio_bootstrap_admits_only_same_origin_packaged_workbench_scripts(client):
    response = client.get("/")
    assert response.status_code == 200
    parser = _Scripts()
    parser.feed(response.text)
    config_script = next(body for _attrs, body in parser.scripts
                         if body.startswith("window.gradio_config = "))
    config = json.loads(config_script.removeprefix("window.gradio_config = ").removesuffix(";"))
    custom_head = _Scripts()
    custom_head.feed(config["head"])
    assert [attrs["src"] for attrs, _body in custom_head.scripts] == list(_HEAD_ASSETS)
    for asset in ASSETS:
        assert (f"/api/ui-session/{asset}") in _HEAD_ASSETS
    assert all(attrs == {"src": source, "defer": None} and body == ""
               for (attrs, body), source in zip(custom_head.scripts, _HEAD_ASSETS, strict=True))
    csp = response.headers["content-security-policy"]
    script_policy = next(item for item in csp.split(";") if item.strip().startswith("script-src "))
    nonce = re.search(r"'nonce-([A-Za-z0-9_-]{32})'", script_policy)[1]
    assert all(attrs["nonce"] == nonce for attrs, _body in parser.scripts)
    assert "'unsafe-eval'" not in script_policy and "'unsafe-inline'" not in script_policy
    assert "script-src-attr 'none'" in csp


def test_crypto_info_callback_uses_only_token_and_selected_session(demo, monkeypatch):
    calls = []
    expected = {"session_id": "owned-session", "integrity_verification": "not_performed"}
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **_kwargs: calls.append(args) or expected)
    fn = callback(demo, "load_crypto_info")
    assert len(fn.inputs) == 3 and len(fn.outputs) == 1
    assert isinstance(fn.inputs[0], gr.State)
    assert isinstance(fn.inputs[1], gr.Dropdown)
    assert isinstance(fn.inputs[2], gr.State)
    assert isinstance(fn.outputs[0], gr.JSON)
    assert fn.outputs[0].value == {}
    assert fn.fn("bearer-token", "owned-session", "owned-session") == expected
    assert calls == [("bearer-token", "GET", "/api/sessions/owned-session/crypto-info")]
    calls.clear()
    assert fn.fn("", "owned-session", "owned-session") == fn.fn("bearer-token", None, None) == {}
    assert calls == []
    load_cipher = callback(demo, "load_cipher")
    assert len(load_cipher.outputs) == 1
    assert fn.outputs[0] not in load_cipher.outputs
    button = next(item for item in demo.blocks.values()
                  if isinstance(item, gr.Button) and item.value == "Tải bản mã")
    assert button.elem_id == "btn-cipher-load"
    dependencies = [item for item in demo.config["dependencies"]
                    if (button._id, "click") in item["targets"]]
    assert {item["id"] for item in dependencies} == {fn._id, load_cipher._id}
    assert next(item for item in dependencies if item["id"] == fn._id)["api_visibility"] == "private"
    extraction = callback(demo, "extract_cipher_workbench")
    assert extraction.inputs == load_cipher.inputs
    assert len(extraction.outputs) == 1
    assert extraction.outputs[0].elem_id == "cipher-workbench-bridge"
    chained = next(item for item in demo.config["dependencies"]
                   if item["id"] == extraction._id)
    assert chained["trigger_after"] == load_cipher._id
    assert chained["api_visibility"] == "private"


def test_crypto_info_callback_crosses_real_owner_authorization_boundary(demo, client, monkeypatch):
    monkeypatch.setattr(gradio_ui, "_api_client", lambda: client)
    monkeypatch.setattr(gradio_ui, "_SESSION_STORE", None)
    monkeypatch.setattr(gradio_ui, "BASE_URL", "http://testserver")
    owner = register_and_login(client, "workbench-owner")
    other = register_and_login(client, "workbench-other")
    created = client.post("/api/sessions", headers={"Authorization": f"Bearer {owner}"}, json={"title": "Owner"})
    assert created.status_code == 201
    session_id = created.json()["id"]
    fn = callback(demo, "load_crypto_info")
    shown = fn.fn(owner, session_id, session_id)
    assert shown["session_id"] == session_id
    assert shown["integrity_verification"] == "not_performed"
    assert fn.fn(other, session_id, session_id) == gr.skip()


def test_selection_change_and_logout_clear_metadata_without_touching_local_fields(demo, monkeypatch):
    fn = callback(demo, "load_crypto_info")
    target = fn.outputs[0]
    clear = callback(demo, "clear_crypto_view")
    assert clear.outputs[1] is target
    cleared = clear.fn("next-session", 4)
    assert cleared[1:] == ({}, "next-session", 5)
    monkeypatch.setattr(gradio_ui, "_api", lambda *_args, **_kwargs: {})

    async def scenario():
        state = SessionState(demo)
        state[fn.inputs[0]._id] = "previous-account"
        logout = callback(demo, "do_logout")
        result = await demo.process_api(logout, [None], state=state)
        outputs = dict(zip((item._id for item in logout.outputs), result["data"], strict=True))
        assert outputs[target._id].root == {}
        assert state[fn.inputs[0]._id] == ""
        assert state[fn.inputs[2]._id] is None
        assert "data-scap-session-clear" in str(outputs)

    asyncio.run(scenario())


@pytest.mark.parametrize("callback_name", ["load_cipher", "load_crypto_info", "extract_cipher_workbench"])
def test_slow_cipher_view_cannot_repopulate_after_selecting_another_conversation(
    demo, monkeypatch, callback_name
):
    entered, release = threading.Event(), threading.Event()
    calls = []

    def api(_token, method, path, *_args, **_kwargs):
        calls.append((method, path))
        assert method == "GET"
        if "/old-session/" in path:
            entered.set()
            assert release.wait(15)
        if callback_name == "load_crypto_info":
            return {"session_id": "fresh-session" if "/fresh-session/" in path else "old-session",
                    "message_counts": {"total": 1}, "integrity_verification": "not_performed"}
        if path.endswith("/messages"):
            return [{"id": 1, "content": "fresh-plaintext" if "/fresh-session/" in path else "old-plaintext"}]
        return [{"id": 1, "role": "user", "ciphertext_preview": "fresh-ciphertext" if "/fresh-session/" in path else "old-ciphertext",
                 "nonce": "public-nonce", "crypto_epoch": 1, "encryption_scheme": "envelope-v1",
                 "created_at": "2026-10-18T00:00:00Z"}]

    monkeypatch.setattr(gradio_ui, "_api", api)

    async def scenario():
        fn, clear = callback(demo, callback_name), callback(demo, "clear_crypto_view")
        state = SessionState(demo)
        state[fn.inputs[0]._id] = "same-account"
        state[fn.inputs[1]._id].choices = [("Old", "old-session"), ("Fresh", "fresh-session")]
        state[fn.inputs[2]._id] = "old-session"
        pending = asyncio.create_task(demo.process_api(fn, [None, "old-session", None], state=state))
        try:
            assert await asyncio.to_thread(entered.wait, 10)
            changed = await demo.process_api(clear, ["fresh-session", None], state=state)
            assert changed["data"][1].root == {}
            assert state[clear.outputs[2]._id] == "fresh-session"
            assert state[clear.outputs[3]._id] == 1
        finally:
            release.set()
        previous = await pending
        assert previous["data"] == [gr.skip()]
        assert previous["changed_state_ids"] == []
        fresh = await demo.process_api(fn, [None, "fresh-session", None], state=state)
        assert fresh["data"] != [gr.skip()]
        if callback_name == "extract_cipher_workbench":
            payload = bridge_payload(fresh["data"][0])
            assert payload["session_id"] == "fresh-session"
            assert payload["records"][0]["content"] == "fresh-plaintext"
            assert "old-" not in json.dumps(payload)
            assert len(calls) == 4
        else:
            assert "fresh-" in str(fresh["data"])
            assert "old-session" not in str(fresh["data"])
            assert "old-ciphertext" not in str(fresh["data"])
            assert len(calls) == 2

    asyncio.run(scenario())


@pytest.mark.parametrize("callback_name", ["load_cipher", "load_crypto_info", "extract_cipher_workbench"])
@pytest.mark.parametrize("new_selection", ["fresh-session", None])
def test_queued_cipher_view_for_previous_selection_does_not_read_api(
    demo, monkeypatch, callback_name, new_selection
):
    calls = []

    def api(*args, **_kwargs):
        calls.append(args)
        if callback_name == "load_crypto_info":
            return {"session_id": "fresh-session", "message_counts": {"total": 0}}
        return []

    monkeypatch.setattr(gradio_ui, "_api", api)

    async def scenario():
        fn, clear = callback(demo, callback_name), callback(demo, "clear_crypto_view")
        state = SessionState(demo)
        state[fn.inputs[0]._id] = "same-account"
        state[fn.inputs[1]._id].choices = [("Old", "old-session"), ("Fresh", "fresh-session")]
        state[fn.inputs[2]._id] = "old-session"
        await demo.process_api(clear, [new_selection, None], state=state)
        assert state[fn.inputs[2]._id] == new_selection
        # Admission happened for the old selection, but invocation only starts
        # after change/clearing. The fresh generation alone cannot reject it.
        previous = await demo.process_api(fn, [None, "old-session", None], state=state)
        assert previous["data"] == [gr.skip()]
        assert calls == []
        if new_selection is not None:
            fresh = await demo.process_api(fn, [None, "fresh-session", None], state=state)
            assert fresh["data"] != [gr.skip()]
            assert len(calls) == 1
            assert "/fresh-session/" in calls[0][2]

    asyncio.run(scenario())


@pytest.mark.parametrize("callback_name", ["load_crypto_info", "extract_cipher_workbench"])
def test_slow_metadata_response_cannot_publish_after_logout(demo, monkeypatch, callback_name):
    entered, release = threading.Event(), threading.Event()

    def api(_token, _method, path, *_args, **_kwargs):
        if path == "/api/auth/logout":
            return {}
        assert path.startswith("/api/sessions/old-session/")
        entered.set()
        assert release.wait(15)
        if callback_name == "extract_cipher_workbench":
            if path.endswith("/messages"):
                return [{"id": 1, "content": "PRIVATE OLD PLAINTEXT"}]
            return [{"id": 1, "ciphertext_preview": "private-ciphertext"}]
        return {"session_id": "old-session", "message_counts": {"total": 99}}

    monkeypatch.setattr(gradio_ui, "_api", api)

    async def scenario():
        fn, logout = callback(demo, callback_name), callback(demo, "do_logout")
        state = SessionState(demo)
        state[fn.inputs[0]._id] = "previous-account"
        state[fn.inputs[1]._id].choices = [("Old", "old-session")]
        state[fn.inputs[2]._id] = "old-session"
        pending = asyncio.create_task(demo.process_api(fn, [None, "old-session", None], state=state))
        try:
            assert await asyncio.to_thread(entered.wait, 10)
            await demo.process_api(logout, [None], state=state)
        finally:
            release.set()
        result = await pending
        assert result["data"] == [gr.skip()]
        assert result["changed_state_ids"] == []

    asyncio.run(scenario())


def test_extract_cipher_workbench_builds_bounded_base64_bridge_payload(demo, monkeypatch):
    cipher_rows = [
        {
            "id": "5c14f839",
            "role": "user",
            "ciphertext_preview": "abc123==",
            "nonce": "nonce-1",
            "crypto_epoch": 1,
            "key_version": 1,
            "encryption_scheme": "envelope-v1",
            "created_at": "2026-10-19T05:11:13Z",
        },
        {
            "id": "bb8148d7",
            "role": "assistant",
            "ciphertext_preview": "def456==",
            "nonce": "nonce-2",
            "crypto_epoch": 1,
            "key_version": 1,
            "encryption_scheme": "envelope-v1",
            "created_at": "2026-10-19T05:11:21Z",
        },
    ]
    message_rows = [
        {"id": "5c14f839", "role": "user", "content": "Nội dung câu hỏi"},
        {"id": "bb8148d7", "role": "assistant", "content": "Nội dung phản hồi"},
    ]

    def fake_api(_token, _method, path, *_args, **_kwargs):
        if path.endswith("/ciphertexts"):
            return cipher_rows
        if path.endswith("/messages"):
            return message_rows
        return []

    monkeypatch.setattr(gradio_ui, "_api", fake_api)
    fn = callback(demo, "extract_cipher_workbench")
    assert fn.fn("bearer-token", "sess-1", "other-session") == gr.skip()
    assert fn.fn("", "sess-1", "sess-1") == ""
    markup = fn.fn("bearer-token", "sess-1", "sess-1")
    match = re.search(
        r'data-scap-cipher-extract="([^"]+)"\s+data-scap-cipher-nonce="([0-9a-f]{16})"',
        markup,
    )
    assert match is not None
    payload = json.loads(base64.b64decode(match.group(1)).decode("utf-8"))
    assert payload["session_id"] == "sess-1"
    assert payload["status"] == "ready"
    assert len(payload["records"]) == 2
    assert payload["records"][1]["id"] == "bb8148d7"
    assert payload["records"][1]["content"] == "Nội dung phản hồi"
    assert (
        payload["records"][1]["context"]
        == "session:sess-1|msg:bb8148d7|role:assistant|epoch:1|scheme:envelope-v1"
    )


@pytest.mark.parametrize("case,expected,calls_expected", [
    ("no_selection", "no_selection", 0), ("empty", "empty", 1),
    ("denied", "unavailable", 1), ("messages_error", "unavailable", 2),
    ("messages_missing", "unavailable", 2),
])
def test_key_restore_reload_receives_explicit_empty_or_unavailable_bridge(
    demo, monkeypatch, case, expected, calls_expected,
):
    calls = []

    def api(_token, _method, path, *_args, **_kwargs):
        calls.append(path)
        if case == "denied" or (case == "messages_error" and path.endswith("/messages")):
            raise gr.Error("PRIVATE API ERROR must not reach the bridge")
        if case == "empty" or path.endswith("/messages"):
            return []
        return [{"id": 139, "ciphertext_preview": "PRIVATE METADATA"}]

    monkeypatch.setattr(gradio_ui, "_api", api)
    selected = None if case == "no_selection" else "selected-session"
    fn = callback(demo, "extract_cipher_workbench")
    markup = fn.fn("authenticated-token", selected, selected)
    assert bridge_payload(markup) == {
        "session_id": selected or "", "records": [], "status": expected,
    }
    assert len(calls) == calls_expected
    assert "PRIVATE" not in markup
    # Every attempt has a new nonce, so an already-open controller can observe
    # completion even when the selected conversation's result stays empty.
    assert fn.fn("authenticated-token", selected, selected) != markup
    calls.clear()
    assert fn.fn("", selected, selected) == ""
    assert fn.fn("authenticated-token", "old-session", "new-session") == gr.skip()
    assert calls == []


def test_restore_reload_bridge_reads_complete_owned_conversation_and_denies_another_account(
    demo, client, app, monkeypatch,
):
    monkeypatch.setattr(gradio_ui, "_api_client", lambda: client)
    monkeypatch.setattr(gradio_ui, "_SESSION_STORE", None)
    monkeypatch.setattr(gradio_ui, "BASE_URL", "http://testserver")
    owner = register_and_login(client, "restore-conversation-owner")
    other = register_and_login(client, "restore-conversation-other")
    response = client.post("/api/sessions", headers={"Authorization": f"Bearer {owner}"},
                           json={"title": "Uploaded file conversation"})
    assert response.status_code == 201
    session_id = response.json()["id"]
    original = "Nội dung tệp gốc 🔐\nDòng thứ hai không bị mất."
    reply = "Phản hồi từ trợ lý: bản tóm tắt riêng."
    with app.state.database.session_factory() as db:
        app.state.chat_service.store_message(db, session_id, "user", original)
        app.state.chat_service.store_message(db, session_id, "assistant", reply)
        db.commit()
    fn = callback(demo, "extract_cipher_workbench")
    payload = bridge_payload(fn.fn(owner, session_id, session_id))
    assert payload["status"] == "ready"
    assert [(row["role"], row["content"]) for row in payload["records"]] == [
        ("user", original), ("assistant", reply),
    ]
    assert all(row["context"].startswith(f"session:{session_id}|msg:")
               for row in payload["records"])
    denied = bridge_payload(fn.fn(other, session_id, session_id))
    assert denied == {"session_id": session_id, "records": [], "status": "unavailable"}
    assert original not in json.dumps(denied, ensure_ascii=False)

