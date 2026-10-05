"""Only administrators can read operational counters, including the real UI."""

from sqlalchemy import select

from src.app import gradio_ui
from src.app.models import User
from tests.conftest import register_and_login
from tests.test_monitoring_availability import Clock


def admin_token(client, app):
    username = "operational-admin"
    register_and_login(client, username)
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == username))
        user.role = "admin"
        db.commit()
    response = client.post("/api/auth/login", json={
        "username": username, "password": "Correct Horse Battery1",
    })
    assert response.status_code == 200
    return response.json()["access_token"]


def test_operational_status_and_alerts_do_not_bypass_admin_authorization(client):
    denied = client.get("/api/admin/availability")
    assert denied.status_code == 401
    assert "http_recent" not in denied.json()
    token = register_and_login(client, "operational-ordinary")
    denied = client.get("/api/admin/availability", headers={"Authorization": f"Bearer {token}"})
    assert denied.status_code == 403
    assert "http_recent" not in denied.json()
    assert client.get("/api/admin/stats", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_authenticated_admin_sees_recent_counters_alerts_and_they_expire(client, app):
    clock = Clock()
    app.state.availability_monitor.clock = clock
    token = admin_token(client, app)
    monitor = app.state.availability_monitor
    for _ in range(5):
        monitor.observe_response(503, 2, streaming=False)
    response = client.get("/api/admin/availability", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["http_recent"]["throttled_responses"] == 5
    assert {alert["code"] for alert in payload["alerts"]} >= {"http_overload", "http_server_errors"}
    assert token not in response.text and "operational-admin" not in response.text
    assert "192.0.2." not in response.text and "Authorization" not in response.text
    clock.now += 60
    response = client.get("/api/admin/availability", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["http_recent"]["requests"] == 0
    assert response.json()["alerts"] == []


def test_real_admin_ui_renders_http_window_and_current_capacity_without_secrets(client, app, monkeypatch):
    app.state.availability_monitor.clock = Clock()
    token = admin_token(client, app)
    for _ in range(20):
        app.state.availability_monitor.observe_response(503, 2, streaming=False)

    def api(token, method, path, data=None, params=None):
        response = client.request(method, path, json=data, params=params,
                                  headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200, response.text
        return response.json()

    monkeypatch.setattr(gradio_ui, "_api", api)
    demo = gradio_ui.build_ui()
    callback = next(fn for fn in demo.fns.values()
                    if fn.fn is not None and fn.fn.__name__ == "refresh_admin")
    streams = app.state.stream_capacity
    for _ in range(streams.maximum):
        assert streams.acquire()
    try:
        output = callback.fn(token)
    finally:
        for _ in range(streams.maximum):
            streams.release()
    assert len(output) == 8
    assert "Quan sát HTTP gần đây (60 giây)" in output[4]
    assert "Độ trễ đến header" in output[4]
    assert "Cảnh báo vận hành" in output[5]
    assert "Tỷ lệ lỗi máy chủ" in output[5]
    assert "Các vị trí luồng giao diện đang đầy" in output[5]
    assert "chưa kết luận có tấn công" in output[5]
    assert "tính cả yêu cầu đang lấy số liệu" in output[5]
    assert token not in output[4] + output[5]
    assert "operational-admin" not in output[4] + output[5]
