"""Optional integration checks against a disposable local PostgreSQL cluster.

SCAP_TEST_POSTGRES_URL must name the administrative ``scap_security_tests``
database on a loopback address. Every case creates and drops its own UUID-named
database. A fresh cluster is required: existing runtime roles are never changed.
"""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace

import psycopg
import pytest
from psycopg import sql
from sqlalchemy import event, select, text
from sqlalchemy.engine import URL, make_url

from src.app.audit_chain import verify_chain
from src.app.db import Database
from src.app.ids import Detection, PersistentIntrusionState
from src.app.models import AuditEvent, IntrusionSource, User
from tests import test_account_transactions as account_regressions
from tests import test_admin_transactions as admin_regressions
from tests import test_auth_completion_transactions as auth_completion
from tests import test_ids_request_transactions as ids_transactions
from tests import test_ids_runtime as ids_regressions
from tests.test_privileged_step_up import ADMIN_PASSWORD, auth, create_account, login

pytestmark = pytest.mark.skipif(
    not os.getenv("SCAP_TEST_POSTGRES_URL"),
    reason="SCAP_TEST_POSTGRES_URL is not set; disposable PostgreSQL checks are optional",
)


@dataclass(frozen=True, repr=False)
class _Cluster:
    administrative_url: URL
    runtime_password: str


def _validated_url(value: str) -> URL:
    try:
        url = make_url(value)
        host = url.host or ""
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pytest.fail("SCAP_TEST_POSTGRES_URL must use a literal loopback address or localhost")
    if (url.get_backend_name() != "postgresql" or not loopback
            or url.database != "scap_security_tests" or url.query or not url.username):
        pytest.fail(
            "Refusing PostgreSQL integration target: use a loopback URL, database "
            "scap_security_tests, an administrative username, and no query overrides"
        )
    # Resolve localhost explicitly so DNS/service settings cannot redirect the
    # destructive fixture outside the disposable local cluster.
    return url.set(drivername="postgresql+psycopg", host="127.0.0.1" if host == "localhost" else host)


def _connect_admin(url: URL):
    return psycopg.connect(
        url.set(drivername="postgresql").render_as_string(hide_password=False),
        connect_timeout=5,
        autocommit=True,
    )


@pytest.fixture(scope="module")
def _postgres_cluster():
    raw_url = os.getenv("SCAP_TEST_POSTGRES_URL")
    if not raw_url:
        pytest.skip("SCAP_TEST_POSTGRES_URL is not set")
    url = _validated_url(raw_url)
    runtime_password = uuid.uuid4().hex
    owned_roles: list[str] = []
    with _connect_admin(url) as connection:
        assert connection.execute("SELECT current_database()").fetchone()[0] == "scap_security_tests"
        present = connection.execute(
            "SELECT rolname FROM pg_roles WHERE rolname IN ('scap_app', 'scap_auditor')"
        ).fetchall()
        if present:
            pytest.fail("Use a fresh disposable cluster: scap_app/scap_auditor already exist")
        try:
            connection.execute(sql.SQL(
                "CREATE ROLE scap_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD {}"
            ).format(sql.Literal(runtime_password)))
            owned_roles.append("scap_app")
            connection.execute(
                "CREATE ROLE scap_auditor NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOINHERIT NOREPLICATION NOBYPASSRLS"
            )
            owned_roles.append("scap_auditor")
            yield _Cluster(url, runtime_password)
        finally:
            for role in reversed(owned_roles):
                connection.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


@pytest.fixture
def _postgres_database(_postgres_cluster):
    cluster = _postgres_cluster
    database_name = "scap_security_" + uuid.uuid4().hex
    owner_url = cluster.administrative_url.set(database=database_name)
    runtime_url = owner_url.set(username="scap_app", password=cluster.runtime_password)
    with _connect_admin(cluster.administrative_url) as connection:
        connection.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(
            sql.Identifier(database_name)
        ))
        try:
            owner = Database(owner_url.render_as_string(hide_password=False))
            try:
                owner.create_all()
                owner.apply_postgres_least_privilege()
            finally:
                owner.engine.dispose()
            yield runtime_url
        finally:
            # The only deletion target is this fixture's generated identifier;
            # neither an environment-provided name nor a pre-existing DB is used.
            connection.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
                sql.Identifier(database_name)
            ))


@pytest.fixture
def settings(settings, _postgres_database):
    return replace(settings, database_url=_postgres_database.render_as_string(hide_password=False))


# Reuse behavioral regressions with PostgreSQL fixtures and real runtime grants.
# Parametrization remains attached to the imported test functions.
test_postgres_admin_create_rechecks_authority = (
    admin_regressions.test_admin_create_rechecks_authority_after_password_work
)
test_postgres_admin_mutation_audit_rollback = (
    admin_regressions.test_admin_mutation_rolls_back_when_audit_insert_fails
)
test_postgres_admin_mutation_revokes_sessions = (
    admin_regressions.test_successful_admin_mutation_has_sealed_audit_and_revokes_target_sessions
)
test_postgres_apps_share_ids_and_unblock = (
    ids_regressions.test_running_apps_share_ids_and_unblock_through_admin_api
)
test_postgres_unblock_audit_rollback = ids_regressions.test_unblock_is_rolled_back_with_failed_admin_audit
test_postgres_ids_storage_off_async_loop = ids_regressions.test_ids_storage_does_not_run_on_the_async_request_loop
test_postgres_ids_storage_failure_closed = ids_regressions.test_unavailable_ids_store_fails_closed_without_leaking_database_error

test_postgres_account_mutation_audit_rollback = (
    account_regressions.test_account_mutation_and_one_time_proofs_roll_back_with_failed_audit
)
test_postgres_account_mutation_rechecks_bearer = (
    account_regressions.test_account_mutation_rejects_logout_after_dependency_authentication
)
test_postgres_passkey_mutation_rechecks_session_and_step_up = (
    account_regressions.test_passkey_registration_rechecks_current_session_and_step_up
)
test_postgres_registration_audit_rollback = auth_completion.test_self_registration_rolls_back_account_when_audit_fails
test_postgres_mfa_challenge_audit_rollback = auth_completion.test_mfa_challenge_login_rehash_rolls_back_when_audit_fails
test_postgres_auth_completion_audit_rollback = auth_completion.test_session_and_consent_changes_roll_back_when_audit_fails
test_postgres_sign_in_batch_audit_rollback = auth_completion.test_sign_in_rolls_back_proofs_session_and_every_required_audit
test_postgres_consent_rechecks_bearer = auth_completion.test_consent_cannot_be_enabled_by_an_inflight_revoked_bearer
test_postgres_ids_request_audit_rollback = ids_transactions.test_ids_request_rolls_back_all_state_and_evidence_on_audit_failure
test_postgres_ids_request_batch_success = ids_transactions.test_ids_request_commits_multiple_signatures_one_ban_and_ordered_seals
test_postgres_concurrent_ids_request_ban = ids_transactions.test_concurrent_ids_requests_make_one_audited_ban_without_bypassing_it


@pytest.fixture
def mail(app):
    recorder = account_regressions.Recorder()
    app.state.mailer.transport = recorder
    app.state.mailer.background = False
    return recorder


def test_postgres_runtime_and_auditor_keep_least_privilege(client, app):
    with app.state.database.session_factory() as db:
        assert db.scalar(text("SELECT current_user")) == "scap_app"
        assert not db.scalar(text("SELECT has_schema_privilege(current_user, 'public', 'CREATE')"))
        assert db.scalar(text("SELECT has_table_privilege(current_user, 'audit_events', 'INSERT')"))
        for table in ("audit_events", "audit_checkpoints"):
            for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
                assert not db.scalar(text(
                    "SELECT has_table_privilege(current_user, :table, :privilege)"
                ), {"table": table, "privilege": privilege})
            assert db.scalar(text(
                "SELECT has_table_privilege('scap_auditor', :table, 'SELECT')"
            ), {"table": table})
        assert not db.scalar(text("SELECT has_table_privilege('scap_auditor', 'users', 'SELECT')"))
        superuser, create_db, create_role, bypass_rls = db.execute(text(
            "SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls "
            "FROM pg_roles WHERE rolname = current_user"
        )).one()
        assert not any((superuser, create_db, create_role, bypass_rls))


def test_postgres_opposite_admin_demotions_serialize_without_deadlock(client, app):
    first_id = create_account(app, "opposite-first", role="admin")
    second_id = create_account(app, "opposite-second", role="admin")
    first_token = login(client, "opposite-first", ADMIN_PASSWORD)
    second_token = login(client, "opposite-second", ADMIN_PASSWORD)
    ready = threading.Barrier(2)
    seen_threads: set[int] = set()
    seen_lock = threading.Lock()

    def before_sql(_connection, _cursor, statement, _parameters, _context, _many):
        normalized = " ".join(statement.lower().split())
        # current_user's earlier activity transaction has an is_active filter.
        # Synchronize only the later mutation claim after both dependencies
        # accepted their respective administrators, before any final row lock.
        if (normalized.startswith("update users set token_version=users.token_version where users.id =")
                and "users.is_active" not in normalized):
            ident = threading.get_ident()
            with seen_lock:
                first_claim = ident not in seen_threads
                seen_threads.add(ident)
            if first_claim:
                ready.wait(timeout=10)

    event.listen(app.state.database.engine, "before_cursor_execute", before_sql)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(
                client.patch, f"/api/admin/users/{second_id}/role",
                headers=auth(first_token), json={"role": "user"},
            )
            second = executor.submit(
                client.patch, f"/api/admin/users/{first_id}/role",
                headers=auth(second_token), json={"role": "user"},
            )
            responses = [first.result(timeout=20), second.result(timeout=20)]
    finally:
        ready.abort()
        event.remove(app.state.database.engine, "before_cursor_execute", before_sql)

    assert len(seen_threads) == 2
    assert sorted(response.status_code for response in responses) == [200, 401], [
        response.text for response in responses
    ]
    with app.state.database.session_factory() as db:
        assert sorted([db.get(User, first_id).role, db.get(User, second_id).role]) == ["admin", "user"]
        audits = list(db.scalars(select(AuditEvent).where(
            AuditEvent.event_type == "admin.user_role_change"
        )))
        assert len(audits) == 1
        assert verify_chain(db, app.state.audit_key).intact


def test_postgres_ids_workers_share_scores_and_emit_one_block_transition(client, app, settings):
    workers = 8
    ready = threading.Barrier(workers)
    source = "192.0.2.144"
    hit = Detection(
        rule_id="PG-SHARED-SCORE", severity="low", engine="test",
        description="Concurrent IDS score integration test", source_ip=source,
        path="/test", method="GET", evidence_sha256="0" * 64,
    )

    def record_from_worker(_):
        database = Database(settings.database_url, runtime_limits=True)
        try:
            state = PersistentIntrusionState(database.session_factory, block_threshold=workers)
            ready.wait(timeout=10)
            return state.record(hit)
        finally:
            database.engine.dispose()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        transitions = list(executor.map(record_from_worker, range(workers)))
    assert sum(transitions) == 1
    state = PersistentIntrusionState(app.state.database.session_factory, block_threshold=workers)
    assert state.is_blocked(source)[0]
    assert len(state.recent()) == workers
    with app.state.database.session_factory() as db:
        row = db.get(IntrusionSource, source)
        assert len(json.loads(row.score_times_json)) == workers
        assert row.blocked_until is not None
