"""Bounded HTTP checks against a disposable loopback SCAP child process.

No target URL, real database, environment credentials or paid AI is accepted.
This verifies selected controls; it is not an Internet DDoS benchmark.
"""

from __future__ import annotations

import argparse
import ctypes
import http.client
import json
import logging
import multiprocessing
import os
import socket
import tempfile
import threading
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import uvicorn

from scripts import demo_local
from src.app.demo_seed import DEMO_PASSPHRASE
from src.app.siem import SIEM_LOGGER_NAME

MAX_REQUESTS = 160
MAX_OPEN_CONNECTIONS = 5  # Four held bodies plus one recovery/overload probe.
MAX_SECONDS = 100
MAX_RSS_BYTES = 1024 * 1024 * 1024


def current_rss_bytes() -> int | None:
    """Current resident memory of this process, never a fabricated zero."""
    if os.name == "nt":
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in (
                    "peak_working_set", "working_set", "paged_peak", "paged",
                    "nonpaged_peak", "nonpaged", "pagefile", "pagefile_peak",
                )
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            return int(counters.working_set)
        return None
    try:
        # Linux current RSS, not resource.ru_maxrss's lifetime peak.
        resident_pages = int(Path("/proc/self/statm").read_text().split()[1])
        return resident_pages * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError, AttributeError):
        return None


class FakeProvider:
    def __init__(self):
        self.release = threading.Event()
        self.release.set()
        self.lock = threading.Lock()
        self.calls = self.active = self.maximum_active = 0

    def generate(self, _prompt, **_kwargs):
        with self.lock:
            self.calls += 1
            self.active += 1
            self.maximum_active = max(self.maximum_active, self.active)
        try:
            if not self.release.wait(6):
                raise RuntimeError("Synthetic provider deadline.")
            return "Synthetic offline response."
        finally:
            with self.lock:
                self.active -= 1

    def snapshot(self):
        with self.lock:
            return {"calls": self.calls, "active": self.active, "maximum_active": self.maximum_active}


def _serve(directory, listener, control, profile, stop_seconds, rss_limit):
    """Runs only in a fresh spawn process, with explicitly isolated settings."""
    port = listener.getsockname()[1]
    settings = demo_local.demo_settings(Path(directory), port)
    if profile == "capacity":
        settings = replace(settings, request_max_concurrent=4, request_ip_max_concurrent=8,
                           password_max_concurrent=1, ai_max_concurrent=1)
    elif profile == "rate":
        settings = replace(settings, request_window_seconds=2, request_ip_max_attempts=6,
                           request_global_max_attempts=600)
    else:
        control.send({"error": "invalid_profile"})
        return
    started, cpu_started = time.monotonic(), time.process_time()
    resource_state = {"baseline_rss_bytes": None, "peak_rss_bytes": None, "stop_reason": None}
    state_lock = threading.Lock()
    finished = threading.Event()

    def guard():
        # Includes app import/build/seed, not just the serving phase. A hard
        # stop affects this disposable child only; the parent removes its data.
        while not finished.wait(.1):
            rss = current_rss_bytes()
            reason = None
            if rss is None:
                reason = "rss_unavailable"
            elif rss > rss_limit:
                reason = "memory_limit"
            elif time.monotonic() - started > stop_seconds:
                reason = "time_limit"
            elif time.process_time() - cpu_started > 30:
                reason = "cpu_time_limit"
            with state_lock:
                if rss is not None:
                    resource_state["peak_rss_bytes"] = max(resource_state["peak_rss_bytes"] or rss, rss)
                if reason:
                    resource_state["stop_reason"] = reason
            if reason:
                # Do not wait for a hung SDK/import to cooperate with shutdown.
                os._exit(3)

    guard_thread = threading.Thread(target=guard, daemon=True)
    guard_thread.start()
    try:
        with (patch.object(demo_local, "demo_settings", return_value=settings),
              patch("src.app.siem.emit_security_event")):
            with demo_local.demo_application(Path(directory), port) as app:
                logging.getLogger(SIEM_LOGGER_NAME).disabled = True
                provider = FakeProvider()
                app.state.chat_service.ai._client = provider
                server = uvicorn.Server(uvicorn.Config(
                    app, host="127.0.0.1", port=port, http="h11", access_log=False,
                    proxy_headers=False, log_level="critical", limit_concurrency=64,
                    backlog=128, timeout_keep_alive=2, timeout_graceful_shutdown=2,
                    h11_max_incomplete_event_size=16_384,
                ))
                with state_lock:
                    resource_state["baseline_rss_bytes"] = current_rss_bytes()
                probe_state = {"completed": False, "failed": False}

                def occupy_provider():
                    # SQLite serializes web writer transactions across users.
                    # Occupy the real shared AI budget without holding a DB
                    # transaction, then exercise the real HTTP chat rejection.
                    try:
                        app.state.chat_service.ai.generate(
                            "Synthetic capacity reservation.", [], allow_external_ai=True)
                        probe_state["completed"] = True
                    except Exception:  # noqa: BLE001 - synthetic fault only
                        probe_state["failed"] = True

                def snapshot():
                    with state_lock:
                        resources = dict(resource_state)
                    elapsed = time.monotonic() - started
                    cpu = time.process_time() - cpu_started
                    resources.update(wall_seconds=round(elapsed, 3), cpu_seconds=round(cpu, 3),
                                     cpu_percent_one_core=round(100 * cpu / max(elapsed, .001), 2))
                    return {"requests": app.state.request_capacity.snapshot(),
                            "password": app.state.password_service.capacity.snapshot(),
                            "rejections": app.state.availability_monitor.snapshot()["rejections"],
                            "provider": {**provider.snapshot(), **probe_state}, "resources": resources}

                def commands():
                    while not server.started and not finished.wait(.02):
                        pass
                    if finished.is_set():
                        return
                    control.send({"ready": True, "profile": profile, "snapshot": snapshot()})
                    while not finished.is_set():
                        try:
                            if not control.poll(.1):
                                continue
                            command = control.recv()
                            if command == "snapshot":
                                control.send(snapshot())
                            elif command == "hold_provider":
                                provider.release.clear()
                                threading.Thread(target=occupy_provider, daemon=True).start()
                                control.send({"ok": True})
                            elif command == "release_provider":
                                provider.release.set()
                                control.send({"ok": True})
                            elif command == "stop":
                                provider.release.set()
                                control.send(snapshot())
                                server.should_exit = True
                                return
                        except (EOFError, OSError):
                            provider.release.set()
                            server.should_exit = True
                            return

                threads = [threading.Thread(target=commands, daemon=True)]
                for thread in threads:
                    thread.start()
                try:
                    server.run(sockets=[listener])
                finally:
                    finished.set()
                    provider.release.set()
                    for thread in threads:
                        thread.join(timeout=1)
    except Exception:  # noqa: BLE001 - no private exception contents in reports
        try:
            control.send({"error": "child_failed"})
        except (OSError, EOFError):
            pass
    finally:
        finished.set()
        guard_thread.join(timeout=1)
        listener.close()
        control.close()


@dataclass
class Sample:
    status: int
    milliseconds: float
    retry_after: bool
    payload: dict | list | None = None  # Private transient state, never serialized.


def summarize(samples):
    def latencies(statuses):
        values = sorted(sample.milliseconds for sample in samples if sample.status in statuses)
        if not values:
            return {"samples": 0}
        return {"samples": len(values), "p50_ms": round(values[(len(values)-1)//2], 2),
                "p95_ms": round(values[min(len(values)-1, (95*len(values)+99)//100-1)], 2)}

    return {"requests": len(samples),
            "statuses": dict(Counter(str(sample.status) for sample in samples)),
            "success_latency": latencies({200, 201, 204}),
            "rejection_latency": latencies({429, 503}),
            "retry_after_on_rejections": all(sample.retry_after for sample in samples
                                               if sample.status in {429, 503})}


class LocalServer:
    def __init__(self, directory, profile, deadline):
        self.deadline = deadline
        self.requests = 0
        self.last_snapshot = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        context = multiprocessing.get_context("spawn")
        self.control, child_control = context.Pipe()
        self.process = context.Process(target=_serve, args=(
            str(directory), self.listener, child_control, profile,
            max(.1, deadline-time.monotonic()), MAX_RSS_BYTES,
        ), daemon=True)
        try:
            self.process.start()
            child_control.close()
            ready = self._receive(40)
            if not ready.get("ready"):
                raise RuntimeError("Isolated server startup failed.")
            self.last_snapshot = ready["snapshot"]
        except BaseException:
            child_control.close()
            self.close()
            raise

    def _receive(self, maximum=4):
        if not self.control.poll(self.timeout(maximum)):
            raise RuntimeError("Local check deadline.")
        result = self.control.recv()
        if "error" in result:
            raise RuntimeError("Local child failed.")
        return result

    def timeout(self, maximum):
        remaining = self.deadline-time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Local check deadline.")
        return min(maximum, remaining)

    def pause(self, seconds):
        # A required recovery wait cannot silently consume the deadline.
        if self.timeout(seconds) < seconds:
            raise RuntimeError("Recovery exceeds the remaining deadline.")
        time.sleep(seconds)

    def rpc(self, command="snapshot"):
        self.control.send(command)
        result = self._receive()
        if command in {"snapshot", "stop"}:
            self.last_snapshot = result
            if result["resources"]["stop_reason"]:
                raise RuntimeError("Resource guard stopped the check.")
        return result

    def wait(self, predicate, timeout=4):
        until = min(self.deadline, time.monotonic() + timeout)
        while time.monotonic() < until:
            state = self.rpc()
            if predicate(state):
                return state
            time.sleep(.03)
        raise RuntimeError("Expected state did not arrive.")

    def request(self, method, path, *, payload=None, headers=None):
        # There is deliberately no URL/host argument or redirect following.
        if not path.startswith("/") or path.startswith("//") or "\r" in path or "\n" in path:
            raise ValueError("Only fixed local paths are accepted.")
        self._reserve_request()
        body = json.dumps(payload).encode() if payload is not None else None
        fixed_headers = dict(headers or {})
        if body is not None:
            fixed_headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout(7))
        started = time.perf_counter()
        try:
            connection.request(method, path, body=body, headers=fixed_headers)
            connection.sock.settimeout(self.timeout(7))
            response = connection.getresponse()
            content = response.read(65_537)
            if len(content) > 65_536:
                raise RuntimeError("Response safety ceiling.")
            parsed = None
            if content and "application/json" in response.getheader("Content-Type", ""):
                parsed = json.loads(content)
            retry = response.getheader("Retry-After", "")
            return Sample(response.status, (time.perf_counter()-started)*1000,
                          retry.isdigit() and int(retry) > 0, parsed)
        finally:
            connection.close()

    def slow_body(self):
        self._reserve_request()
        connection = socket.create_connection(("127.0.0.1", self.port), timeout=self.timeout(5))
        try:
            connection.sendall(b"POST /api/auth/login HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                                b"Content-Type: application/json\r\nContent-Length: 64\r\n"
                                b"Connection: close\r\n\r\n{")
        except BaseException:
            connection.close()
            raise
        return connection

    def _reserve_request(self):
        if self.requests >= MAX_REQUESTS or time.monotonic() >= self.deadline:
            raise RuntimeError("Request/time safety ceiling.")
        self.requests += 1

    def close(self):
        if self.process.is_alive():
            try:
                self.rpc("stop")
            except (OSError, EOFError, RuntimeError):
                pass
            self.process.join(timeout=4)
            if self.process.is_alive():
                self.process.terminate()
                self.process.join(timeout=3)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(timeout=2)
        self.listener.close()
        self.control.close()


@contextmanager
def isolated_server(directory, profile, deadline):
    directory.mkdir()
    server = LocalServer(directory, profile, deadline)
    try:
        yield server
    finally:
        server.close()


def _require(sample, status):
    if sample.status != status:
        raise RuntimeError("Unexpected HTTP result.")
    return sample


def _login(server, username):
    sample = _require(server.request("POST", "/api/auth/login", payload={
        "username": username, "password": DEMO_PASSPHRASE,
    }), 200)
    return {"Authorization": "Bearer " + sample.payload["access_token"]}


def _conversation(server, headers):
    result = _require(server.request("POST", "/api/sessions", headers=headers,
                                     payload={"title": "Synthetic control check"}), 201)
    return "/api/sessions/" + result.payload["id"] + "/messages"


def run_checks(*, quick=False, progress=lambda _label: None):
    report = {"schema_version": 1, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "isolated_loopback_http", "passed": False, "phases": [],
              "safety": {"max_requests_per_child": MAX_REQUESTS, "max_open_load_connections": MAX_OPEN_CONNECTIONS,
                         "max_work_seconds": MAX_SECONDS, "cleanup_budget_seconds": 14,
                         "rss_limit_bytes": MAX_RSS_BYTES, "rss_sampling_seconds": 0.1,
                         "ai": "synthetic_offline", "data": "temporary_synthetic"},
              "coverage": {"body_timeout": "skipped_quick" if quick else "not_completed",
                           "internet_ddos": "not_tested", "production_capacity": "not_measured",
                           "protocol": "h11"}}
    deadline = time.monotonic() + MAX_SECONDS
    try:
        with tempfile.TemporaryDirectory(prefix="scap-load-check-") as temporary:
            with isolated_server(Path(temporary)/"capacity", "capacity", deadline) as server:
                user_headers, admin_headers = _login(server, "demo.user"), _login(server, "demo.boss")
                second_headers = _login(server, "demo.mod")
                for headers in (user_headers, second_headers):
                    _require(server.request("PATCH", "/api/auth/ai-consent", headers=headers,
                                            payload={"ai_data_consent": True}), 200)
                baseline = [server.request("GET", "/api/health") for _ in range(24)]
                _require(server.request("GET", "/api/sessions", headers=user_headers), 200)
                report["phases"].append({"name": "baseline", "passed": all(s.status == 200 for s in baseline),
                                         **summarize(baseline)})
                progress("baseline")

                holders = []
                try:
                    for _ in range(4):
                        holders.append(server.slow_body())
                    server.wait(lambda state: state["requests"]["active"] == 4)
                    denied = server.request("GET", "/api/health")
                    _require(denied, 503)
                    if not denied.retry_after:
                        raise RuntimeError("Missing retry guidance.")
                finally:
                    for holder in holders:
                        holder.close()
                server.wait(lambda state: state["requests"]["active"] == 0)
                recovered = _require(server.request("GET", "/api/health"), 200)
                report["phases"].append({"name": "slow_body_disconnect_capacity", "passed": True,
                                         **summarize([denied, recovered])})
                progress("slow_body_disconnect_capacity")

                second_path = _conversation(server, second_headers)
                server.rpc("hold_provider")
                try:
                    state = server.wait(lambda state: state["provider"]["active"] == 1)
                    calls_before = state["provider"]["calls"]
                    busy = _require(server.request("POST", second_path, headers=second_headers,
                                    payload={"content": "Explain bounded resources."}), 503)
                    after = server.rpc()
                    if not busy.retry_after or after["provider"]["calls"] != calls_before:
                        raise RuntimeError("Provider busy control failed.")
                finally:
                    server.rpc("release_provider")
                server.wait(lambda state: state["provider"]["completed"])
                recovered = _require(server.request("POST", second_path, headers=second_headers,
                                payload={"content": "Explain successful recovery."}), 201)
                report["phases"].append({"name": "ai_capacity_fault_and_http_recovery", "passed": True,
                                         "fault": "core_provider_slot_held_without_db_transaction",
                                         **summarize([busy, recovered])})
                progress("ai_capacity_fault_and_http_recovery")

                if not quick:
                    started = time.perf_counter()
                    with server.slow_body() as slow:
                        data = bytearray()
                        while b"\r\n" not in data and len(data) < 4096:
                            slow.settimeout(server.timeout(36))
                            part = slow.recv(512)
                            if not part:
                                break
                            data.extend(part)
                    elapsed = time.perf_counter()-started
                    status = int(bytes(data).split(b"\r\n", 1)[0].split()[1])
                    if status != 408 or not 25 <= elapsed <= 36:
                        raise RuntimeError("Body deadline control failed.")
                    server.wait(lambda state: state["requests"]["active"] == 0)
                    report["phases"].append({"name": "slow_body_deadline", "passed": True,
                                             "status": status, "elapsed_seconds": round(elapsed, 3)})
                    report["coverage"]["body_timeout"] = "checked"
                    progress("slow_body_deadline")
                verified = _require(server.request("GET", "/api/admin/audit/verify", headers=admin_headers), 200)
                if not verified.payload.get("chain_intact"):
                    raise RuntimeError("Audit recovery check failed.")
                _require(server.request("GET", "/api/sessions", headers=user_headers), 200)
                state = server.wait(lambda state: state["requests"]["active"] == 0)
                report["capacity_resources"] = state["resources"]
                report["capacity_controls"] = {"request_limit": 4, "password_limit": 1,
                                                "provider_limit": 1, "rejections": state["rejections"]}
                report["phases"].append({"name": "db_crypto_audit_recovery", "passed": True})
                progress("db_crypto_audit_recovery")

            with isolated_server(Path(temporary)/"rate", "rate", deadline) as server:
                # Sequential pacing deliberately isolates the temporal quota
                # from concurrency. Spoofed forwarding headers must not reset it.
                burst = [server.request("GET", "/api/health", headers={"X-Forwarded-For": f"192.0.2.{n}"})
                         for n in range(12)]
                if not any(s.status == 429 for s in burst) or not all(s.retry_after for s in burst if s.status == 429):
                    raise RuntimeError("Rate control failed.")
                server.pause(2.1)
                recovery = _require(server.request("GET", "/api/health"), 200)
                report["phases"].append({"name": "ip_quota_and_spoof_recovery", "passed": True,
                                         **summarize(burst + [recovery]), "window_seconds": 2, "ip_limit": 6})
                report["rate_resources"] = server.rpc()["resources"]
                progress("ip_quota_and_spoof_recovery")
        report["passed"] = all(phase["passed"] for phase in report["phases"])
    except Exception:  # noqa: BLE001 - fixed error only, no token/body/DB path
        report["failure"] = "control_check_failed_or_safety_stop"
    report["duration_seconds"] = round(MAX_SECONDS-(deadline-time.monotonic()), 3)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Kiểm tra HTTP có giới hạn trên SCAP local tạm riêng.")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/security-load-local"))
    parser.add_argument("--quick", action="store_true", help="Bỏ bài chờ timeout body 30 giây; ghi rõ chưa kiểm chứng.")
    args = parser.parse_args(argv)
    report = run_checks(quick=args.quick, progress=lambda label: print("CHECK: " + label, flush=True))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = args.output_dir / "security-load.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    print("Local HTTP control check: " + ("PASS" if report["passed"] else "FAIL"))
    print("Report: " + str(path))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
