"""Mail delivery uses finite memory/disk budgets without real SMTP traffic."""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage

import pytest

from src.app.mailer import MAX_MESSAGE_BYTES, MailBusy, Mailer, MailUnavailable, OutboxTransport


class BlockingTransport:
    def __init__(self):
        self.release = threading.Event()
        self.started = threading.Event()
        self.messages = []
        self.lock = threading.Lock()

    def send(self, message):
        with self.lock:
            self.messages.append(message)
            if len(self.messages) == 2:
                self.started.set()
        if not self.release.wait(5):
            raise TimeoutError("test transport was not released")


def _send(mailer):
    mailer.send("owner@example.com", "Security notice", "A private code", template="test")


def _message(body="A private code"):
    message = EmailMessage()
    message["From"] = "no-reply@scap.local"
    message["To"] = "owner@example.com"
    message["Subject"] = "Security notice"
    message.set_content(body)
    return message


def test_running_and_queued_mail_share_one_finite_budget():
    transport = BlockingTransport()
    mailer = Mailer(transport, "no-reply@scap.local", max_pending=3)
    try:
        _send(mailer)
        _send(mailer)
        assert transport.started.wait(2)
        _send(mailer)  # The two workers are busy; this is the only queue slot.
        with pytest.raises(MailBusy):
            _send(mailer)
        assert mailer.snapshot() == {
            "limit": 3, "active": 3, "rejected": 1,
            "delivered": 0, "failed": 0, "closed": False,
        }
        assert len(transport.messages) == 2
        transport.release.set()
        mailer.flush(timeout=2)
        assert mailer.snapshot()["active"] == 0
        assert mailer.snapshot()["delivered"] == 3
        _send(mailer)
        mailer.flush(timeout=2)
        assert mailer.snapshot()["delivered"] == 4
    finally:
        transport.release.set()
        mailer.close(timeout=2)


def test_concurrent_submitters_cannot_overrun_pending_budget():
    transport = BlockingTransport()
    mailer = Mailer(transport, "no-reply@scap.local", max_pending=4)

    def attempt():
        try:
            _send(mailer)
        except MailBusy:
            return False
        return True

    try:
        with ThreadPoolExecutor(max_workers=12) as submitters:
            results = list(submitters.map(lambda _: attempt(), range(24)))
        assert sum(results) == 4
        assert mailer.snapshot()["active"] == 4
        assert mailer.snapshot()["rejected"] == 20
    finally:
        transport.release.set()
        mailer.close(timeout=2)


def test_failed_delivery_releases_slots_and_does_not_log_private_data(caplog):
    class FailedTransport:
        def send(self, message):
            raise OSError("secret-code owner@example.com private-body")

    mailer = Mailer(FailedTransport(), "no-reply@scap.local", max_pending=1)
    try:
        _send(mailer)
        mailer.flush(timeout=2)
        assert mailer.snapshot()["active"] == 0
        assert mailer.snapshot()["failed"] == 1
        _send(mailer)
        mailer.flush(timeout=2)
        assert mailer.snapshot()["failed"] == 2
        assert "OSError" in caplog.text
        for private in ("secret-code", "owner@example.com", "private-body", "A private code"):
            assert private not in caplog.text
    finally:
        mailer.close(timeout=2)


def test_executor_submission_failure_returns_reserved_slot():
    class RejectingExecutor:
        def submit(self, *args):
            raise RuntimeError("executor stopped")

        def shutdown(self, **kwargs):
            pass

    mailer = Mailer(BlockingTransport(), "no-reply@scap.local", max_pending=1)
    mailer._executor = RejectingExecutor()
    try:
        with pytest.raises(RuntimeError, match="executor stopped"):
            _send(mailer)
        assert mailer.snapshot()["active"] == 0
    finally:
        mailer.close(timeout=0)


def test_close_cancels_queued_messages_and_rejects_new_work_until_restart():
    transport = BlockingTransport()
    mailer = Mailer(transport, "no-reply@scap.local", max_pending=4)
    try:
        _send(mailer)
        _send(mailer)
        assert transport.started.wait(2)
        _send(mailer)
        _send(mailer)
        mailer.close(timeout=0)
        assert mailer.snapshot()["closed"] is True
        assert mailer.snapshot()["active"] == 2
        with pytest.raises(MailBusy):
            _send(mailer)
        with pytest.raises(MailBusy):
            mailer.start()
        transport.release.set()
        mailer.flush(timeout=2)
        assert mailer.snapshot()["active"] == 0
        assert len(transport.messages) == 2  # Cancelled messages never delivered.
        mailer.start()
        _send(mailer)
        mailer.flush(timeout=2)
        assert mailer.snapshot()["delivered"] == 3
    finally:
        transport.release.set()
        mailer.close(timeout=2)


def test_synchronous_delivery_is_also_bounded_and_releases_on_failure():
    transport = BlockingTransport()
    mailer = Mailer(transport, "no-reply@scap.local", background=False, max_pending=1)
    with ThreadPoolExecutor(max_workers=1) as submitters:
        running = submitters.submit(_send, mailer)
        # This transport records the first message before waiting.
        for _ in range(200):
            with transport.lock:
                started = bool(transport.messages)
            if started:
                break
            threading.Event().wait(0.005)
        try:
            assert started
            with pytest.raises(MailBusy):
                _send(mailer)
        finally:
            transport.release.set()
        running.result(timeout=2)
    assert mailer.snapshot()["active"] == 0
    assert mailer._executor is None
    mailer.close(timeout=0)


def test_synchronous_transport_failure_surfaces_only_generic_error_and_releases_slot(caplog):
    class FailedTransport:
        def send(self, message):
            raise OSError("private-body owner@example.com secret-code")

    mailer = Mailer(FailedTransport(), "no-reply@scap.local", background=False, max_pending=1)
    try:
        with pytest.raises(MailUnavailable) as failure:
            _send(mailer)
        assert str(failure.value) == "Security email delivery is temporarily unavailable."
        assert mailer.snapshot()["active"] == 0
        assert mailer.snapshot()["failed"] == 1
        for private in ("private-body", "owner@example.com", "secret-code"):
            assert private not in str(failure.value)
            assert private not in caplog.text
    finally:
        mailer.close(timeout=0)


def test_synchronous_mailer_reports_outbox_full_without_deleting_existing_mail(tmp_path):
    retained = tmp_path / "retained.eml"
    retained.write_bytes(b"retained secret email")
    mailer = Mailer(
        OutboxTransport(tmp_path, max_files=1), "no-reply@scap.local", background=False,
    )
    try:
        with pytest.raises(MailUnavailable):
            _send(mailer)
        assert mailer.snapshot()["active"] == 0
        assert mailer.snapshot()["failed"] == 1
        assert retained.read_bytes() == b"retained secret email"
        assert list(tmp_path.iterdir()) == [retained]
    finally:
        mailer.close(timeout=0)


@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_invalid_capacity_is_rejected(value):
    with pytest.raises(ValueError):
        Mailer(None, "no-reply@scap.local", max_pending=value)


def test_oversized_and_invalid_mail_never_enters_queue():
    mailer = Mailer(BlockingTransport(), "no-reply@scap.local")
    with pytest.raises(MailUnavailable):
        mailer.send("a@example.com", "test", "x" * (MAX_MESSAGE_BYTES + 1), template="test")
    with pytest.raises(MailUnavailable):
        mailer.send("a@example.com\nBcc: b@example.com", "test", "short", template="test")
    assert mailer.snapshot()["active"] == 0
    assert mailer._executor is None
    mailer.close(timeout=0)


def test_existing_mail_is_preserved_when_outbox_file_budget_is_full(tmp_path):
    retained = tmp_path / "existing.eml"
    retained.write_bytes(b"retained secret email")
    transport = OutboxTransport(tmp_path, max_files=2)
    transport.send(_message())
    with pytest.raises(MailBusy):
        transport.send(_message())
    assert retained.read_bytes() == b"retained secret email"
    assert len(list(tmp_path.glob("*.eml"))) == 2


def test_outbox_byte_budget_includes_existing_files(tmp_path):
    retained = tmp_path / "existing.eml"
    retained.write_bytes(b"retained secret email")
    incoming = _message()
    limit = retained.stat().st_size + len(bytes(incoming))
    transport = OutboxTransport(tmp_path, max_bytes=limit)
    transport.send(incoming)
    with pytest.raises(MailBusy):
        transport.send(incoming)
    assert retained.read_bytes() == b"retained secret email"
    assert sum(file.stat().st_size for file in tmp_path.iterdir()) == limit


def test_empty_outbox_rejects_one_mail_larger_than_its_byte_budget(tmp_path):
    transport = OutboxTransport(tmp_path, max_bytes=1)
    with pytest.raises(MailBusy):
        transport.send(_message())
    assert list(tmp_path.iterdir()) == []


def test_outbox_rejects_oversized_message_without_creating_directory(tmp_path):
    directory = tmp_path / "not-created"
    transport = OutboxTransport(directory)
    with pytest.raises(MailUnavailable):
        transport.send(_message("x" * (MAX_MESSAGE_BYTES + 1)))
    assert not directory.exists()


def test_outbox_instances_serialize_the_same_directory_quota(tmp_path):
    transports = [OutboxTransport(tmp_path, max_files=1) for _ in range(8)]

    def attempt(transport):
        try:
            transport.send(_message())
        except MailBusy:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as senders:
        accepted = list(senders.map(attempt, transports))
    assert sum(accepted) == 1
    assert len(list(tmp_path.glob("*.eml"))) == 1


def _symlink(target, link, *, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("Creating symlinks is unavailable for this Windows account.")


def test_outbox_symlink_directory_never_writes_to_target(tmp_path):
    target = tmp_path / "private-target"
    target.mkdir()
    link = tmp_path / "linked-outbox"
    _symlink(target, link, directory=True)
    with pytest.raises(MailUnavailable):
        OutboxTransport(link).send(_message())
    assert list(target.iterdir()) == []


def test_outbox_symlink_parent_never_creates_child_in_target(tmp_path):
    target = tmp_path / "private-target"
    target.mkdir()
    link = tmp_path / "linked-parent"
    _symlink(target, link, directory=True)
    with pytest.raises(MailUnavailable):
        OutboxTransport(link / "child").send(_message())
    assert list(target.iterdir()) == []


def test_outbox_unsafe_entry_never_modifies_link_target(tmp_path):
    target = tmp_path / "private-target"
    target.write_bytes(b"keep secret")
    directory = tmp_path / "outbox"
    directory.mkdir(mode=0o700)
    _symlink(target, directory / "existing.eml")
    with pytest.raises(MailUnavailable):
        OutboxTransport(directory).send(_message())
    assert target.read_bytes() == b"keep secret"
    assert len(list(directory.iterdir())) == 1


def test_outbox_hardlink_entry_is_rejected_without_modifying_target(tmp_path):
    target = tmp_path / "private-target"
    target.write_bytes(b"keep secret")
    directory = tmp_path / "outbox"
    directory.mkdir(mode=0o700)
    try:
        os.link(target, directory / "existing.eml")
    except (OSError, NotImplementedError):
        pytest.skip("Hard links are not supported by this filesystem.")
    with pytest.raises(MailUnavailable):
        OutboxTransport(directory).send(_message())
    assert target.read_bytes() == b"keep secret"
    assert len(list(directory.iterdir())) == 1


def test_outbox_exclusive_creation_does_not_overwrite_existing_mail(tmp_path, monkeypatch):
    class FixedDate:
        @staticmethod
        def now(zone):
            return FixedDate()

        def strftime(self, format):
            return "fixed-time"

    retained = tmp_path / ("fixed-time-" + "a" * 32 + ".eml")
    retained.write_bytes(b"retained secret email")
    monkeypatch.setattr("src.app.mailer.datetime", FixedDate)
    monkeypatch.setattr("src.app.mailer.secrets.token_hex", lambda _: "a" * 32)
    with pytest.raises(FileExistsError):
        OutboxTransport(tmp_path).send(_message())
    assert retained.read_bytes() == b"retained secret email"


@pytest.mark.skipif(os.name == "nt", reason="Windows privacy uses directory ACLs, not POSIX mode bits.")
def test_outbox_directory_and_files_are_private_on_posix(tmp_path):
    directory = tmp_path / "outbox"
    OutboxTransport(directory).send(_message())
    assert directory.stat().st_mode & 0o777 == 0o700
    assert next(directory.iterdir()).stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name == "nt", reason="Windows privacy uses directory ACLs, not POSIX mode bits.")
def test_existing_world_readable_outbox_is_rejected_without_mutation(tmp_path):
    directory = tmp_path / "outbox"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    with pytest.raises(MailUnavailable):
        OutboxTransport(directory).send(_message())
    assert directory.stat().st_mode & 0o777 == 0o755
    assert list(directory.iterdir()) == []
