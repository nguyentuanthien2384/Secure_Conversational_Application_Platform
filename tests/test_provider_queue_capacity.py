from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace

import gradio as gr
import httpx
import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from gradio.data_classes import PredictBodyInternal

from src.app import gradio_ui, security
from src.app.config import Settings
from src.app.gradio_ui import build_ui
from src.app.security import SlidingWindowRateLimiter
from src.app.services import AI_BUSY_MESSAGE, AIProviderBusy, AIProviderError, AIService
from src.core.ai_core import gemini_ai
from src.core.ai_core.gemini_ai import GeminiClient


class EchoProvider:
    def __init__(self) -> None:
        self.calls = 0

    def generate(self, *_args, **_kwargs) -> str:
        self.calls += 1
        return "A safe response."


def _generate(service: AIService) -> tuple[str, list[str]]:
    return service.generate("Explain concurrency.", [], allow_external_ai=True)


def test_provider_overload_is_shared_across_instances_and_recovers(settings: Settings) -> None:
    configured = replace(settings, ai_max_concurrent=1)
    entered = threading.Event()
    release = threading.Event()

    class BlockingProvider:
        def generate(self, *_args, **_kwargs) -> str:
            entered.set()
            assert release.wait(5), "Test did not release the upstream call."
            return "A safe response."

    first = AIService(configured)
    first._client = BlockingProvider()
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(_generate, first)
        try:
            assert entered.wait(5), "The first request never reached the provider."
            # Constructing another app/service must not reset active reservations.
            second = AIService(configured)
            upstream = EchoProvider()
            second._client = upstream
            with pytest.raises(AIProviderBusy, match=AI_BUSY_MESSAGE):
                _generate(second)
            assert upstream.calls == 0
        finally:
            release.set()
        assert pending.result(timeout=5) == ("A safe response.", [])

    assert _generate(second) == ("A safe response.", [])
    assert upstream.calls == 1


@pytest.mark.parametrize("failure", [RuntimeError("upstream failed"), asyncio.CancelledError()])
def test_provider_capacity_recovers_after_failure_or_cancellation(
    settings: Settings, failure: BaseException
) -> None:
    configured = replace(settings, ai_max_concurrent=1)

    class FailingProvider:
        def generate(self, *_args, **_kwargs) -> str:
            raise failure

    service = AIService(configured)
    service._client = FailingProvider()
    expected = AIProviderError if isinstance(failure, Exception) else type(failure)
    with pytest.raises(expected):
        _generate(service)

    # An unsuccessful/cancelled call must not permanently consume the slot.
    service._client = EchoProvider()
    assert _generate(service) == ("A safe response.", [])


@pytest.mark.parametrize("window_seconds", [60, 86_400])
def test_global_provider_budget_blocks_upstream_and_recovers_at_window_boundary(
    settings: Settings, monkeypatch, window_seconds: int
) -> None:
    now = [100.0]
    monkeypatch.setattr(security, "time", SimpleNamespace(monotonic=lambda: now[0]))
    configured = replace(
        settings,
        ai_global_max_attempts=2 if window_seconds == 60 else 10,
        ai_daily_max_attempts=2 if window_seconds == 86_400 else 10,
    )
    limiter = SlidingWindowRateLimiter()
    first = AIService(configured, provider_limiter=limiter)
    second = AIService(configured, provider_limiter=limiter)
    provider = EchoProvider()
    first._client = second._client = provider
    _generate(first)
    _generate(second)
    with pytest.raises(AIProviderBusy) as blocked:
        _generate(first)
    assert blocked.value.retry_after == window_seconds
    assert provider.calls == 2

    now[0] += window_seconds - 1
    with pytest.raises(AIProviderBusy) as nearly_expired:
        _generate(second)
    assert nearly_expired.value.retry_after == 1
    assert provider.calls == 2

    now[0] += 1
    assert _generate(second) == ("A safe response.", [])
    assert provider.calls == 3


def test_failed_provider_call_still_consumes_global_budget(settings: Settings) -> None:
    service = AIService(
        replace(settings, ai_global_max_attempts=1), provider_limiter=SlidingWindowRateLimiter()
    )

    class FailingProvider:
        def generate(self, *_args, **_kwargs) -> str:
            raise RuntimeError("upstream failed")

    service._client = FailingProvider()
    with pytest.raises(AIProviderError):
        _generate(service)
    provider = EchoProvider()
    service._client = provider
    with pytest.raises(AIProviderBusy) as blocked:
        _generate(service)
    assert blocked.value.retry_after > 1
    assert provider.calls == 0


def test_budget_backend_failure_blocks_upstream_and_releases_capacity(settings: Settings) -> None:
    class BrokenLimiter:
        def allow(self, *_args):
            raise ConnectionError("backend unavailable")

    service = AIService(replace(settings, ai_max_concurrent=1), provider_limiter=BrokenLimiter())
    provider = EchoProvider()
    service._client = provider
    with pytest.raises(AIProviderError):
        _generate(service)
    assert provider.calls == 0

    service.provider_limiter = SlidingWindowRateLimiter()
    assert _generate(service) == ("A safe response.", [])
    assert provider.calls == 1


@pytest.mark.parametrize(
    ("extra_config", "expected"),
    [
        (None, 1_024),
        ({"max_output_tokens": 8_192}, 1_024),
        ({"maxOutputTokens": 8_192}, 1_024),
        ({"max_output_tokens": 128}, 128),
        ({"max_output_tokens": None}, 1_024),
    ],
)
def test_gemini_applies_deployment_token_cap_to_actual_sdk_config(
    monkeypatch, extra_config, expected: int
) -> None:
    captured = []

    def generate_content(**kwargs):
        captured.append(kwargs["config"])
        return SimpleNamespace(
            candidates=[SimpleNamespace(content=SimpleNamespace(parts=[SimpleNamespace(text="ok")]))]
        )

    monkeypatch.setattr(
        gemini_ai.genai, "Client",
        lambda **_kwargs: SimpleNamespace(models=SimpleNamespace(generate_content=generate_content)),
    )
    client = GeminiClient(api_key="unit-test-key", max_output_tokens=1_024)
    assert client.generate("Hello", extra_config=extra_config) == "ok"
    assert captured[0].max_output_tokens == expected


def test_ai_service_passes_configured_token_cap_to_provider(settings: Settings, monkeypatch) -> None:
    captured = {}

    def fake_client(**kwargs):
        captured.update(kwargs)
        return EchoProvider()

    monkeypatch.setattr(gemini_ai, "GeminiClient", fake_client)
    AIService(replace(settings, google_genai_api_key="unit-test-key", ai_max_output_tokens=512))
    assert captured["max_output_tokens"] == 512


def test_gradio_shows_retry_after_when_api_provider_is_busy(monkeypatch) -> None:
    class BusyApiClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def post(self, *_args, **_kwargs):
            return httpx.Response(
                503, json={"detail": AI_BUSY_MESSAGE}, headers={"Retry-After": "1"}
            )

    warnings: list[str] = []
    monkeypatch.setattr(httpx, "Client", BusyApiClient)
    monkeypatch.setattr(gradio_ui, "_browser_context_headers", lambda: {})
    monkeypatch.setattr(gr, "Warning", warnings.append)
    callback = gradio_ui._guard(
        lambda: gradio_ui._api(None, "POST", "/api/sessions/test/messages", {"content": "Hello"}),
        2,
    )
    assert callback() == (gr.skip(), gr.skip())
    assert len(warnings) == 1
    assert AI_BUSY_MESSAGE in warnings[0]
    assert "Thử lại sau 1 giây." in warnings[0]


def test_gradio_waiting_queue_rejects_overflow_then_accepts_after_removal() -> None:
    ui = build_ui(queue_max_size=2, concurrency_limit=3)
    queue = ui._queue
    fn_index, fn = next(iter(ui.fns.items()))
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/gradio_api/queue/join",
            "query_string": b"",
            "headers": [],
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
    )

    async def push(session: str):
        body = PredictBodyInternal(
            fn_index=fn_index, data=[], session_hash=session, request=request
        )
        return await queue.push(body, request, username=None)

    async def scenario() -> None:
        first = await push("first")
        assert first[0] and first[2] == "success"
        assert (await push("second"))[2] == "success"
        rejected = await push("third")
        assert rejected[0] is False and rejected[2] == "queue_full"
        assert len(queue) == 2
        assert queue.event_queue_per_concurrency_id[fn.concurrency_id].concurrency_limit == 3

        await queue.remove_from_queue(first[1])
        assert len(queue) == 1
        assert (await push("retry"))[2] == "success"
        assert len(queue) == 2

    # Do not start workers: pending requests stay queued to exercise the real
    # Gradio admission/removal paths deterministically, without network load.
    asyncio.run(scenario())


@pytest.mark.parametrize("route", ["run", "api"])
def test_direct_gradio_predict_cannot_bypass_bounded_queue(route: str) -> None:
    ui = build_ui(queue_max_size=1, concurrency_limit=1)
    fn_index, fn = next(iter(ui.fns.items()))
    calls: list[bool] = []

    def forbidden_callback(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("Direct predict bypassed the queue.")

    fn.fn = forbidden_callback
    with TestClient(ui.app) as client:
        response = client.post(
            f"/gradio_api/{route}/{fn.api_name}",
            json={"data": [], "fn_index": fn_index},
        )
    assert response.status_code == 404
    assert calls == []
