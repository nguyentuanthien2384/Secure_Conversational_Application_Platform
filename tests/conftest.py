from __future__ import annotations

import base64
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.app.config import Settings
from src.app.main import create_app


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    key = base64.urlsafe_b64encode(b"K" * 32).decode("ascii")
    return Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        secret_key="test-secret-key-that-is-long-enough-for-jwt-signing",
        master_encryption_key=key,
        access_token_minutes=30,
        login_window_seconds=60,
        login_max_attempts=5,
        message_window_seconds=60,
        message_max_attempts=20,
        allow_demo_ai=True,
        docs_enabled=False,
    )


@pytest.fixture()
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture()
def client(app):
    with TestClient(app) as test_client:
        yield test_client


def register_and_login(
    client: TestClient, username: str, password: str = "Correct Horse Battery1"
) -> str:
    response = client.post("/api/auth/register", json={"username": username, "password": password})
    assert response.status_code == 201, response.text
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]
