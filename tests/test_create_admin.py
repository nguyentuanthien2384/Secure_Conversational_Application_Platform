"""One-off administrator provisioning is isolated, private and atomic."""

from __future__ import annotations

import warnings
from dataclasses import replace

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from scripts import create_admin as provision
from src.app.audit_chain import derive_audit_key, seal_event, verify_chain
from src.app.audit_checkpoint import AuditCheckpointError
from src.app.config import Settings
from src.app.db import Database
from src.app.models import AuditEvent, User
from src.app.security import PasswordBreachCheckUnavailable, PasswordService

PASSWORD = "River Copper Evening Lantern 9274"


@pytest.fixture
def admin_settings():
    return Settings(
        environment="production",
        security_profile="standard",
        secret_key="administrator-provisioning-test-key-only",
        password_breach_check=False,
        audit_chain_enabled=True,
    )


@pytest.fixture
def database(tmp_path):
    isolated = Database(f"sqlite:///{tmp_path / 'provisioning.db'}")
    isolated.create_all()
    try:
        yield isolated
    finally:
        isolated.engine.dispose()


def counts(database):
    with database.session_factory() as db:
        return (
            db.scalar(select(func.count(User.id))),
            db.scalar(select(func.count(AuditEvent.id))),
        )


def test_new_admin_hash_and_sealed_audit_commit_together(admin_settings, database, monkeypatch):
    events = []
    monkeypatch.setattr(provision, "emit_security_event", lambda *args, **kwargs: events.append((args, kwargs)))
    user_id = provision.create_administrator(
        admin_settings, database, username="Owner.Demo", password=PASSWORD
    )
    with database.session_factory() as db:
        user = db.get(User, user_id)
        assert user.username == "owner.demo"
        assert user.role == "admin" and user.is_active
        assert user.password_hash != PASSWORD
        assert PasswordService().verify(user.password_hash, PASSWORD)
        audit = db.scalar(select(AuditEvent))
        assert audit.event_type == "admin.bootstrap_create"
        assert audit.target_id == user_id and audit.actor_id is None
        assert PASSWORD not in audit.details_json and user.username not in audit.details_json
        verification = verify_chain(db, derive_audit_key(admin_settings.secret_key))
        assert verification.intact and verification.verified == 1
    assert counts(database) == (1, 1)
    assert len(events) == 1
    assert PASSWORD not in repr(events) and "owner.demo" not in repr(events)


def test_existing_user_is_not_promoted_reset_or_screened(admin_settings, database, monkeypatch):
    with database.session_factory() as db, db.begin():
        db.add(User(username="existing.user", password_hash="unchanged-hash", role="user", is_active=False))
    monkeypatch.setattr(provision.PwnedPasswordChecker, "is_compromised", lambda *_: pytest.fail("no password screening"))
    with pytest.raises(provision.AdminProvisioningError, match="already exists"):
        provision.create_administrator(admin_settings, database, username="Existing.User", password=PASSWORD)
    with database.session_factory() as db:
        user = db.scalar(select(User))
        assert user.password_hash == "unchanged-hash" and user.role == "user" and not user.is_active
    assert counts(database) == (1, 0)


@pytest.mark.parametrize("password", ["short", "passwordpassword", "x" * 129, " secret phrase with space "])
def test_password_policy_failure_never_exposes_input_or_writes(admin_settings, database, password):
    with pytest.raises(provision.AdminProvisioningError) as error:
        provision.create_administrator(admin_settings, database, username="valid.user", password=password)
    assert password not in str(error.value)
    assert counts(database) == (0, 0)


@pytest.mark.parametrize("username", ["ab", "a" * 33, "owner@host", "bad\nuser", "user/name"])
def test_username_policy_matches_application(admin_settings, database, username):
    with pytest.raises(provision.AdminProvisioningError):
        provision.create_administrator(admin_settings, database, username=username, password=PASSWORD)
    assert counts(database) == (0, 0)


@pytest.mark.parametrize("overrides", [
    {"environment": "development"}, {"environment": "test"},
    {"security_profile": "high"}, {"audit_chain_enabled": False}, {"secret_key": "short"},
])
def test_unsupported_profile_refused_before_database_access(admin_settings, overrides):
    with pytest.raises(provision.AdminProvisioningError):
        provision.create_administrator(replace(admin_settings, **overrides), None, username="owner.demo", password=PASSWORD)


def test_configured_breach_check_rejects_compromised_password(admin_settings, database, monkeypatch):
    configured = []

    class Breached:
        def __init__(self, *, enabled):
            configured.append(enabled)

        def is_compromised(self, password):
            assert password == PASSWORD
            return True

    monkeypatch.setattr(provision, "PwnedPasswordChecker", Breached)
    with pytest.raises(provision.AdminProvisioningError, match="public breach"):
        provision.create_administrator(replace(admin_settings, password_breach_check=True), database, username="owner.demo", password=PASSWORD)
    assert configured == [True] and counts(database) == (0, 0)


def test_breach_screening_failure_does_not_write_or_expose_password(admin_settings, database, monkeypatch):
    def unavailable(*_):
        raise PasswordBreachCheckUnavailable(PASSWORD)

    monkeypatch.setattr(provision.PwnedPasswordChecker, "is_compromised", unavailable)
    with pytest.raises(provision.AdminProvisioningError) as error:
        provision.create_administrator(admin_settings, database, username="owner.demo", password=PASSWORD)
    assert PASSWORD not in str(error.value) and counts(database) == (0, 0)


def test_audit_failure_rolls_back_flushed_admin(admin_settings, database, monkeypatch):
    def refuse(*_):
        raise SQLAlchemyError("sensitive statement " + PASSWORD)

    monkeypatch.setattr(provision, "seal_event", refuse)
    with pytest.raises(provision.AdminProvisioningError) as error:
        provision.create_administrator(admin_settings, database, username="owner.demo", password=PASSWORD)
    assert PASSWORD not in str(error.value) and counts(database) == (0, 0)


def test_broken_chain_is_preserved_and_refuses_new_admin(admin_settings, database):
    with database.session_factory() as db, db.begin():
        event = AuditEvent(event_type="existing.event", outcome="success", details_json="{}")
        seal_event(db, event, derive_audit_key(admin_settings.secret_key))
        db.add(event)
    with database.session_factory() as db, db.begin():
        event = db.scalar(select(AuditEvent))
        event.details_json = '{"changed":true}'
        original_hash = event.entry_hash
    with pytest.raises(provision.AdminProvisioningError, match="not intact"):
        provision.create_administrator(admin_settings, database, username="owner.demo", password=PASSWORD)
    with database.session_factory() as db:
        event = db.scalar(select(AuditEvent))
        assert event.entry_hash == original_hash and event.details_json == '{"changed":true}'
    assert counts(database) == (0, 1)


def test_noninteractive_cli_refuses_before_loading_environment(monkeypatch, capsys):
    monkeypatch.setattr(provision.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(provision.Settings, "from_env", lambda: pytest.fail("must not read environment"))
    monkeypatch.setattr(provision.getpass, "getpass", lambda *_: pytest.fail("must not prompt"))
    assert provision.main(["--username", "owner.demo"]) == 1
    assert "interactive terminal" in capsys.readouterr().err


def prepare_cli(monkeypatch, settings):
    monkeypatch.setattr(provision.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(provision.Settings, "from_env", lambda: settings)


def test_cli_success_uses_hidden_prompts_and_no_password_output(admin_settings, database, monkeypatch, capsys):
    prepare_cli(monkeypatch, replace(admin_settings, database_url="postgresql+psycopg://scap_app@db/secure_chat"))
    passwords = iter((PASSWORD, PASSWORD))
    monkeypatch.setattr(provision.getpass, "getpass", lambda *_: next(passwords))
    monkeypatch.setattr(provision, "Database", lambda *_args, **_kwargs: database)
    monkeypatch.setattr(provision, "configure_siem_logging", lambda *_: None)
    assert provision.main(["--username", "owner.demo"]) == 0
    output = capsys.readouterr()
    assert "Administrator created" in output.out
    assert PASSWORD not in output.out + output.err
    assert counts(database) == (1, 1)


def test_cli_password_mismatch_never_connects(admin_settings, monkeypatch, capsys):
    prepare_cli(monkeypatch, replace(admin_settings, database_url="postgresql+psycopg://scap_app@db/secure_chat"))
    passwords = iter((PASSWORD, "different password phrase"))
    monkeypatch.setattr(provision.getpass, "getpass", lambda *_: next(passwords))
    monkeypatch.setattr(provision, "Database", lambda *_args, **_kwargs: pytest.fail("must not connect"))
    assert provision.main(["--username", "owner.demo"]) == 1
    output = capsys.readouterr()
    assert "did not match" in output.err and PASSWORD not in output.err


def test_cli_forbids_getpass_fallback_echo(admin_settings, monkeypatch, capsys):
    prepare_cli(monkeypatch, replace(admin_settings, database_url="postgresql+psycopg://scap_app@db/secure_chat"))

    def fallback(*_):
        warnings.warn("cannot hide password", provision.getpass.GetPassWarning, stacklevel=1)
        pytest.fail("must stop before a fallback input")

    monkeypatch.setattr(provision.getpass, "getpass", fallback)
    monkeypatch.setattr(provision, "Database", lambda *_args, **_kwargs: pytest.fail("must not connect"))
    assert provision.main(["--username", "owner.demo"]) == 1
    assert "Admin creation failed" in capsys.readouterr().err


def test_cli_does_not_dump_configuration_failure(monkeypatch, capsys):
    monkeypatch.setattr(provision.sys.stdin, "isatty", lambda: True)

    def invalid_configuration():
        raise RuntimeError("credential=" + PASSWORD)

    monkeypatch.setattr(provision.Settings, "from_env", invalid_configuration)
    assert provision.main(["--username", "owner.demo"]) == 1
    assert PASSWORD not in capsys.readouterr().err


def test_cli_refuses_sqlite_before_password_prompt(admin_settings, monkeypatch, capsys):
    prepare_cli(monkeypatch, replace(admin_settings, database_url="sqlite:///:memory:"))
    monkeypatch.setattr(provision.getpass, "getpass", lambda *_: pytest.fail("must not prompt"))
    assert provision.main(["--username", "owner.demo"]) == 1
    assert "PostgreSQL" in capsys.readouterr().err


def test_cli_has_no_password_argument_or_argument_value_echo(capsys):
    with pytest.raises(SystemExit) as error:
        provision.main(["--username", "owner.demo", "--password", PASSWORD])
    assert error.value.code == 2
    assert PASSWORD not in capsys.readouterr().err


# --- High-security profile: the external WORM provisioning workflow ---------


@pytest.fixture
def high_settings(admin_settings, tmp_path):
    token = tmp_path / "worm-token"
    token.write_text("test-only-worm-token", encoding="utf-8")
    return replace(
        admin_settings,
        security_profile="high",
        audit_worm_endpoint="https://worm.example.test/checkpoints",
        audit_worm_token_file=str(token),
        audit_checkpoint_interval=1,
        audit_max_unanchored_events=0,
    )


class FakeWorm:
    """Accepts ``fail_after`` deliveries (None: all), then reports an outage."""

    def __init__(self, fail_after=None):
        self.fail_after = fail_after
        self.delivered = []

    def __call__(self, document, _checkpoint_id):
        if self.fail_after is not None and len(self.delivered) >= self.fail_after:
            raise AuditCheckpointError("simulated WORM outage")
        self.delivered.append(document["last_event_id"])
        return "sha256:" + "a" * 64


def worm_service(settings, monkeypatch, worm):
    service = provision.checkpoint_service_for(settings)
    monkeypatch.setattr(service, "_deliver", worm)
    return service


def seal_startup_event(database, settings):
    with database.session_factory() as db, db.begin():
        event = AuditEvent(event_type="application.startup", outcome="success", details_json="{}")
        seal_event(db, event, derive_audit_key(settings.secret_key))
        db.add(event)


def forbid_screening(monkeypatch):
    monkeypatch.setattr(
        provision.PwnedPasswordChecker, "is_compromised", lambda *_: pytest.fail("must refuse first")
    )


def test_high_profile_refuses_without_a_remote_worm_sink(high_settings):
    assert provision.checkpoint_service_for(replace(high_settings, security_profile="standard")) is None
    with pytest.raises(provision.AdminProvisioningError, match="WORM"):
        provision.create_administrator(high_settings, None, username="owner.demo", password=PASSWORD)
    with pytest.raises(provision.AdminProvisioningError, match="WORM"):
        provision.create_administrator(
            replace(high_settings, audit_worm_endpoint=""), None,
            username="owner.demo", password=PASSWORD,
        )


def test_high_admin_event_is_anchored_before_success(high_settings, database, monkeypatch):
    seal_startup_event(database, high_settings)
    events = []
    monkeypatch.setattr(provision, "emit_security_event", lambda event_type, **_: events.append(event_type))
    worm = FakeWorm()
    service = worm_service(high_settings, monkeypatch, worm)
    user_id = provision.create_administrator(
        high_settings, database, username="owner.demo", password=PASSWORD, checkpoint_service=service
    )
    with database.session_factory() as db:
        created = db.scalar(select(AuditEvent).where(AuditEvent.event_type == "admin.bootstrap_create"))
        assert created.target_id == user_id
        verification = service.verify_latest(db)
    # The preflight anchors the unanchored startup tail, then the admin event.
    assert worm.delivered == [1, created.id]
    assert verification.fully_anchored and verification.last_event_id == created.id
    assert events == ["admin.bootstrap_create"]
    assert counts(database) == (1, 2)


@pytest.mark.parametrize("already_anchored", [False, True])
def test_high_refuses_while_the_worm_sink_is_unreachable(
    high_settings, database, monkeypatch, already_anchored
):
    seal_startup_event(database, high_settings)
    if already_anchored:
        # An idle, fully anchored tail still proves reachability by replaying it.
        healthy = worm_service(high_settings, monkeypatch, FakeWorm())
        with database.session_factory() as db:
            assert healthy.anchor(db) is not None
    forbid_screening(monkeypatch)
    service = worm_service(high_settings, monkeypatch, FakeWorm(fail_after=0))
    with pytest.raises(provision.AdminProvisioningError, match="WORM sink is unavailable"):
        provision.create_administrator(
            high_settings, database, username="owner.demo", password=PASSWORD, checkpoint_service=service
        )
    assert counts(database) == (0, 1)


def test_high_refuses_when_an_anchored_audit_tail_was_deleted(high_settings, database, monkeypatch):
    seal_startup_event(database, high_settings)
    seal_startup_event(database, high_settings)
    service = worm_service(high_settings, monkeypatch, FakeWorm())
    with database.session_factory() as db:
        assert service.anchor(db).last_event_id == 2
        db.delete(db.get(AuditEvent, 2))
        db.commit()
    forbid_screening(monkeypatch)
    with pytest.raises(provision.AdminProvisioningError, match="does not match"):
        provision.create_administrator(
            high_settings, database, username="owner.demo", password=PASSWORD, checkpoint_service=service
        )
    assert counts(database) == (0, 1)


def test_high_delivery_failure_after_commit_is_pending_not_refused(high_settings, database, monkeypatch):
    seal_startup_event(database, high_settings)
    events = []
    monkeypatch.setattr(
        provision, "emit_security_event",
        lambda event_type, outcome="success", **_: events.append((event_type, outcome)),
    )
    # The preflight delivery succeeds; the sink fails right after the commit.
    service = worm_service(high_settings, monkeypatch, FakeWorm(fail_after=1))
    with pytest.raises(provision.AdminAnchorPending) as pending:
        provision.create_administrator(
            high_settings, database, username="owner.demo", password=PASSWORD, checkpoint_service=service
        )
    assert PASSWORD not in str(pending.value) and "owner.demo" not in str(pending.value)
    with database.session_factory() as db:
        assert db.get(User, pending.value.user_id).role == "admin"
        assert verify_chain(db, derive_audit_key(high_settings.secret_key)).intact
        assert service.verify_latest(db).unanchored_events == 1
    assert events == [("admin.bootstrap_create", "success"), ("audit.checkpoint.delivery_failed", "failure")]
    # The application's next readiness/maintenance pass anchors the sealed tail.
    recovered = worm_service(high_settings, monkeypatch, FakeWorm())
    with database.session_factory() as db:
        assert recovered.ensure_latest_anchored(db).fully_anchored


@pytest.mark.parametrize(("fail_after", "exit_code", "stream", "message"), [
    (None, 0, "out", "anchored in the WORM sink"),
    (0, 3, "err", "checkpoint was not delivered"),
])
def test_cli_high_reports_anchoring_outcome(
    high_settings, database, monkeypatch, capsys, fail_after, exit_code, stream, message
):
    prepare_cli(monkeypatch, replace(high_settings, database_url="postgresql+psycopg://scap_app@db/secure_chat"))
    passwords = iter((PASSWORD, PASSWORD))
    monkeypatch.setattr(provision.getpass, "getpass", lambda *_: next(passwords))
    monkeypatch.setattr(provision, "Database", lambda *_args, **_kwargs: database)
    monkeypatch.setattr(provision, "configure_siem_logging", lambda *_: None)
    real_factory = provision.checkpoint_service_for

    def factory(settings):
        service = real_factory(settings)
        monkeypatch.setattr(service, "_deliver", FakeWorm(fail_after))
        return service

    monkeypatch.setattr(provision, "checkpoint_service_for", factory)
    assert provision.main(["--username", "owner.demo"]) == exit_code
    output = capsys.readouterr()
    assert message in getattr(output, stream)
    assert PASSWORD not in output.out + output.err
    assert counts(database) == (1, 1)


def test_cli_high_checks_the_worm_token_before_any_password_prompt(high_settings, tmp_path, monkeypatch, capsys):
    prepare_cli(monkeypatch, replace(
        high_settings,
        database_url="postgresql+psycopg://scap_app@db/secure_chat",
        audit_worm_token_file=str(tmp_path / "missing-token"),
    ))
    monkeypatch.setattr(provision.getpass, "getpass", lambda *_: pytest.fail("must not prompt"))
    monkeypatch.setattr(provision, "Database", lambda *_args, **_kwargs: pytest.fail("must not connect"))
    assert provision.main(["--username", "owner.demo"]) == 1
    assert "Admin creation failed" in capsys.readouterr().err
