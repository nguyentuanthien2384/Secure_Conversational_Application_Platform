"""The admin view consumes the real authenticated availability response."""

from sqlalchemy import select

from src.app import gradio_ui
from src.app.models import User
from tests.conftest import register_and_login


def test_admin_refresh_displays_real_worker_snapshot(client, app, monkeypatch):
    register_and_login(client, "capacity-ui-admin")
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "capacity-ui-admin"))
        user.role = "admin"
        db.commit()
    token = client.post("/api/auth/login", json={
        "username": "capacity-ui-admin", "password": "Correct Horse Battery1",
    }).json()["access_token"]

    def api(token, method, path, data=None, params=None):
        response = client.request(method, path, json=data, params=params,
                                  headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200, response.text
        return response.json()

    monkeypatch.setattr(gradio_ui, "_api", api)
    demo = gradio_ui.build_ui()
    callback = next(fn for fn in demo.fns.values()
                    if fn.fn is not None and fn.fn.__name__ == "refresh_admin")
    output = callback.fn(token)
    assert len(output) == 8
    assert "Tài nguyên xử lý hiện tại" in output[4]
    assert "Luồng giao diện" in output[4]
    assert "Audit lấy mẫu" in output[4]
    assert token not in output[4]
    assert "capacity-ui-admin" not in output[4]
