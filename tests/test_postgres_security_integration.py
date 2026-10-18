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
from datetime import timedelta

import psycopg
import pytest
from psycopg import sql
from sqlalchemy import event, inspect, select, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import OperationalError

from src.app.audit_chain import append_lock, seal_event, verify_chain
from src.app.audit_checkpoint import AuditCheckpointError, canonical_checkpoint, sign_checkpoint
from src.app.db import Database, utcnow
from src.app.ids import Detection, PersistentIntrusionState
from src.app.models import AuditCheckpoint, AuditEvent, AuthSession, IntrusionSource, User
from tests import test_account_transactions as account_regressions
from tests import test_admin_transactions as admin_regressions
from tests import test_auth_completion_transactions as auth_completion
from tests import test_data_paging as data_paging
from tests import test_data_transactions as data_transactions
from tests import test_e2ee_prekeys_cursor as prekeys_cursor
from tests import test_ids_request_transactions as ids_transactions
from tests import test_ids_runtime as ids_regressions
from tests import test_passkey_stepup as passkey_stepup
from tests import test_passkey_stepup_migration as passkey_migration
from tests import test_postcommit_notifications as postcommit_notifications
from tests import test_restore_quarantine as restore_quarantine
from tests import test_security_notifications as notification_regressions
from tests import test_security_phone_retention as phone_retention
from tests import test_security_phone_retention_migration as phone_migration
from tests import test_sign_in_geoip_risk as geoip_regressions
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
def settings(settings, _postgres_database, request, tmp_path):
    configured = replace(settings, database_url=_postgres_database.render_as_string(hide_password=False))
    if request.node.name.startswith("test_postgres_notification_"):
        from src.app.notification_config import NotificationSettings

        configured = replace(configured, notification_settings=NotificationSettings(
            push_backend="outbox", sms_backend="outbox", outbox_dir=str(tmp_path / "notices"),
        ))
    return configured


@pytest.fixture(params=[False, True], ids=["old-schema", "partial-column"])
def legacy_database(_postgres_database, _postgres_cluster, request):
    """Exercise owner-run legacy DDL against an isolated PostgreSQL database."""
    owner_url = _postgres_cluster.administrative_url.set(database=_postgres_database.database)
    database = Database(owner_url.render_as_string(hide_password=False))
    with database.session_factory() as db:
        db.add(User(id="legacy-owner", username="legacy-owner", password_hash="unused"))
        db.flush()
        db.add(AuthSession(
            jti="legacy-jti", user_id="legacy-owner", session_family_id="legacy-jti",
            expires_at=utcnow() + timedelta(hours=1),
        ))
        db.commit()
    with database.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE webauthn_challenges")
        connection.exec_driver_sql("""
            CREATE TABLE webauthn_challenges (
                id VARCHAR(36) NOT NULL PRIMARY KEY,
                user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
                purpose VARCHAR(16) NOT NULL,
                challenge VARCHAR(128) NOT NULL,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                consumed_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                CONSTRAINT ck_webauthn_challenge_purpose
                CHECK (purpose IN ('register', 'authenticate'))
            )
        """)
        connection.exec_driver_sql(
            "CREATE INDEX ix_webauthn_challenges_user_id ON webauthn_challenges(user_id)",
        )
        if request.param:
            connection.exec_driver_sql(
                "ALTER TABLE webauthn_challenges ADD COLUMN auth_session_id VARCHAR(36) "
                "REFERENCES auth_sessions(jti) ON DELETE CASCADE",
            )
        connection.exec_driver_sql("""
            INSERT INTO webauthn_challenges
                (id,user_id,purpose,challenge,expires_at,consumed_at,created_at)
            VALUES ('legacy-register','legacy-owner','register','registration-proof',
                    '2026-10-17 12:03:00+00',NULL,'2026-10-17 12:00:00+00'),
                   ('legacy-authenticate',NULL,'authenticate','authentication-proof',
                    '2026-10-17 12:03:00+00','2026-10-17 12:01:00+00','2026-10-17 12:00:00+00')
        """)
        if request.param:
            connection.exec_driver_sql(
                "UPDATE webauthn_challenges SET auth_session_id='legacy-jti' "
                "WHERE id='legacy-register'",
            )
    try:
        yield database, request.param
    finally:
        database.engine.dispose()


# These assertions are shared with SQLite, but execute PostgreSQL's ALTER
# COLUMN/CHECK path and real foreign-key constraints rather than the rebuild.
test_postgres_passkey_legacy_migration = (
    passkey_migration.test_upgrade_preserves_legacy_ceremonies_and_is_idempotent
)
test_postgres_passkey_legacy_constraints = (
    passkey_migration.test_migrated_constraints_enforce_purpose_and_session_cascade
)


def test_postgres_failed_passkey_migration_rolls_back_legacy_schema(legacy_database):
    database, had_column = legacy_database
    before = passkey_migration.legacy_rows(database)

    def fail_new_constraint(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.startswith(
            "ALTER TABLE webauthn_challenges ADD CONSTRAINT ck_webauthn_challenge_purpose",
        ):
            raise OperationalError("simulated CHECK migration failure", None, RuntimeError("test"))

    event.listen(database.engine, "before_cursor_execute", fail_new_constraint)
    try:
        with pytest.raises(OperationalError):
            database.create_all()
    finally:
        event.remove(database.engine, "before_cursor_execute", fail_new_constraint)
    assert passkey_migration.legacy_rows(database) == before
    inspector = inspect(database.engine)
    assert ("auth_session_id" in {
        column["name"] for column in inspector.get_columns("webauthn_challenges")
    }) == had_column
    assert not any(
        "step_up" in check["sqltext"]
        for check in inspector.get_check_constraints("webauthn_challenges")
    )
    database.create_all()
    database.assert_schema_ready()
    assert passkey_migration.legacy_rows(database) == before


@pytest.fixture(params=[True, False], ids=["cascade-fk", "partial-no-fk"])
def legacy_phone_database(_postgres_database, _postgres_cluster, request):
    owner_url = _postgres_cluster.administrative_url.set(database=_postgres_database.database)
    database = Database(owner_url.render_as_string(hide_password=False))
    with database.session_factory() as db:
        db.add(User(id="sms-owner", username="sms-owner", password_hash="unused"))
        db.flush()
        db.add(AuthSession(
            jti="sms-session", user_id="sms-owner", session_family_id="sms-session",
            expires_at=utcnow() + timedelta(hours=1),
        ))
        db.commit()
    session_reference = (
        " REFERENCES auth_sessions(jti) ON DELETE CASCADE" if request.param else ""
    )
    with database.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE security_phone_challenges")
        connection.exec_driver_sql("""
            CREATE TABLE security_phone_challenges (
                id VARCHAR(36) NOT NULL PRIMARY KEY,
                user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                auth_session_id VARCHAR(36) NOT NULL""" + session_reference + """,
                phone_hash VARCHAR(64) NOT NULL, phone_ciphertext TEXT NOT NULL,
                phone_nonce VARCHAR(64) NOT NULL, code_hash VARCHAR(64) NOT NULL,
                attempts INTEGER NOT NULL, expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                consumed_at TIMESTAMP WITH TIME ZONE, created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                CONSTRAINT ck_security_phone_attempts CHECK(attempts >= 0 AND attempts <= 5)
            )
        """)
        for proof_id, session_id in [
            ("legacy-bound", "sms-session"),
            *(([("legacy-orphan", "missing-session")]) if not request.param else []),
        ]:
            connection.execute(text("""
                INSERT INTO security_phone_challenges
                    (id,user_id,auth_session_id,phone_hash,phone_ciphertext,phone_nonce,
                     code_hash,attempts,expires_at,consumed_at,created_at)
                VALUES (:id,'sms-owner',:session,'target-hash','ciphertext','nonce','code-hash',
                        2,'2026-10-17 12:05:00+00',NULL,'2026-10-17 12:00:00+00')
            """), {"id": proof_id, "session": session_id})
    try:
        yield database, request.param
    finally:
        database.engine.dispose()


test_postgres_notification_legacy_migration = (
    phone_migration.test_sms_upgrade_preserves_rows_indexes_and_is_idempotent
)
test_postgres_notification_legacy_constraints = (
    phone_migration.test_sms_upgrade_nulls_expired_bearer_keeps_user_cascade_and_guess_limit
)


def test_postgres_failed_phone_migration_rolls_back_legacy_schema(legacy_phone_database):
    database, had_fk = legacy_phone_database
    before = phone_migration._rows(database)

    def fail_new_constraint(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.startswith(
            "ALTER TABLE security_phone_challenges ADD CONSTRAINT "
            "fk_security_phone_challenges_session_retention",
        ):
            raise OperationalError("simulated SMS migration failure", None, RuntimeError("test"))

    event.listen(database.engine, "before_cursor_execute", fail_new_constraint)
    try:
        with pytest.raises(OperationalError):
            database.create_all()
    finally:
        event.remove(database.engine, "before_cursor_execute", fail_new_constraint)
    assert phone_migration._rows(database) == before
    inspector = inspect(database.engine)
    assert next(
        column for column in inspector.get_columns("security_phone_challenges")
        if column["name"] == "auth_session_id"
    )["nullable"] is False
    keys = [
        key for key in inspector.get_foreign_keys("security_phone_challenges")
        if key["constrained_columns"] == ["auth_session_id"]
    ]
    assert len(keys) == int(had_fk)
    if had_fk:
        assert keys[0]["options"]["ondelete"] == "CASCADE"
    with pytest.raises(RuntimeError, match="SMS"):
        database.assert_schema_ready()
    database.create_all()
    database.assert_schema_ready()
    assert phone_migration._rows(database) == before


# Reuse behavioral regressions with PostgreSQL fixtures and real runtime grants.
# Parametrization remains attached to the imported test functions.
paged_data = data_paging.paged_data
notices = notification_regressions.notices
test_postgres_passkey_exact_bearer = passkey_stepup.test_real_passkey_step_up_grants_only_the_presented_bearer
test_postgres_passkey_scope = passkey_stepup.test_challenge_cannot_move_to_another_account_or_bearer
test_postgres_passkey_invalid_proof = passkey_stepup.test_invalid_assertions_burn_the_bound_challenge_without_elevating
test_postgres_passkey_other_account = passkey_stepup.test_another_accounts_valid_credential_cannot_step_up_this_account
test_postgres_passkey_single_use = passkey_stepup.test_successful_assertion_is_single_use_even_with_zero_sign_count
test_postgres_passkey_purpose_expiry = passkey_stepup.test_expired_and_other_purpose_challenges_cannot_authorize_step_up
test_postgres_passkey_not_login = passkey_stepup.test_step_up_assertion_is_not_a_passwordless_login_assertion
test_postgres_passkey_audit_rollback = passkey_stepup.test_step_up_and_challenge_counter_audit_are_one_transaction
test_postgres_passkey_inflight = passkey_stepup.test_inflight_ceremony_rechecks_exact_bearer_after_revocation
test_postgres_passkey_removed_key = passkey_stepup.test_removed_credential_cannot_reauthenticate_an_outstanding_ceremony
test_postgres_passkey_fallback = passkey_stepup.test_keyless_account_uses_password_fallback_and_anonymous_cannot_get_options
test_postgres_passkey_counter_regression = passkey_stepup.test_step_up_counter_regression_is_rejected
test_postgres_passkey_concurrent_counter = passkey_stepup.test_concurrent_login_and_step_up_never_move_a_credential_counter_backwards
test_postgres_passkey_login_recheck = passkey_stepup.test_passwordless_login_rechecks_account_and_credential_after_candidate_lookup
test_postgres_passkey_login_audit_rollback = passkey_stepup.test_passwordless_and_failed_registration_proofs_roll_back_with_failed_audit
test_postgres_notification_opt_in = notification_regressions.test_push_and_verified_phone_opt_in_are_encrypted_and_scope_owned
test_postgres_notification_proof = notification_regressions.test_proof_is_exact_session_bound_expires_and_has_five_guesses
test_postgres_notification_step_up = notification_regressions.test_sensitive_opt_in_and_opt_out_require_recent_step_up
test_postgres_notification_budget = notification_regressions.test_durable_hourly_issuance_budget_survives_target_change_and_supersedes_old_codes
test_postgres_notification_failed_provider = notification_regressions.test_failed_provider_never_enables_an_unverified_phone
test_postgres_notification_audit = notification_regressions.test_registration_and_audit_roll_back_together
test_postgres_notification_payload = notification_regressions.test_fixed_notice_payloads_fan_out_without_sensitive_context
test_postgres_notification_expired_bearer_budget = phone_retention.test_sms_daily_budget_survives_expired_bearer_retention
test_postgres_notification_opt_out_budget = phone_retention.test_sms_opt_out_invalidates_proofs_without_resetting_issuance_budget
test_postgres_notification_proof_retention = phone_retention.test_sms_proof_retention_keeps_quota_window_and_is_bounded_and_dry_run
test_postgres_geoip_success = geoip_regressions.test_completed_login_adds_advisory_evidence_and_does_not_leak_coordinates
test_postgres_geoip_failed_password = geoip_regressions.test_failed_password_is_not_a_travel_observation
test_postgres_geoip_audit_rollback = geoip_regressions.test_travel_audit_failure_rolls_back_new_bearer_and_login_evidence
test_postgres_geoip_history = geoip_regressions.test_old_location_and_same_ip_do_not_raise_travel
test_postgres_data_audit_rollback = data_transactions.test_data_mutations_and_required_audits_roll_back_together
test_postgres_data_exact_bearer = data_transactions.test_data_mutation_rechecks_the_exact_inflight_bearer
test_postgres_concurrent_session_quota = data_transactions.test_concurrent_creation_cannot_exceed_the_per_owner_quota
test_postgres_prekey_refill_and_rotation = prekeys_cursor.test_device_refills_consumed_prekeys_rotates_signed_key_and_rejects_replay
test_postgres_prekey_audit_rollback = prekeys_cursor.test_prekey_update_and_challenge_roll_back_if_audit_fails
test_postgres_prekey_authority = prekeys_cursor.test_prekey_update_needs_possession_owner_and_recent_step_up
test_postgres_prekey_reuse_and_capacity = prekeys_cursor.test_prekeys_cannot_be_reused_even_after_consumption_and_capacity_is_bounded
test_postgres_compound_e2ee_cursor = prekeys_cursor.test_compound_e2ee_cursor_delivers_tied_timestamps_without_loss_or_duplicates
test_postgres_e2ee_routing_state = prekeys_cursor.test_active_member_can_read_routing_state_and_removed_member_cannot
test_postgres_session_paging = data_paging.test_session_pages_reach_beyond_legacy_cap_and_keep_owner_scope
test_postgres_search_paging = data_paging.test_global_and_current_session_search_pages_count_exact_matches
test_postgres_user_paging = data_paging.test_user_pages_pass_legacy_cap_without_exposing_credentials
test_postgres_paging_limits = data_paging.test_page_parameters_are_bounded
test_postgres_restore_quarantine = restore_quarantine.test_quarantine_retires_bearers_factors_and_prekeys_without_rewriting_audit
test_postgres_restore_quarantine_rollback = restore_quarantine.test_quarantine_failure_rolls_back_all_changes
test_postgres_restore_activation = restore_quarantine.test_review_activation_is_explicit_and_atomic
test_postgres_restore_version_overflow = restore_quarantine.test_quarantine_refuses_token_version_overflow

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

test_postgres_postcommit_login_notice_lookup_failure = (
    postcommit_notifications.test_completed_login_returns_its_single_session_when_notice_lookup_fails
)
test_postgres_postcommit_account_notice_lookup_failure = (
    postcommit_notifications.test_completed_account_change_keeps_response_when_notice_lookup_fails
)
test_postgres_postcommit_notice_session_isolation = (
    postcommit_notifications.test_notice_lookup_uses_a_separate_short_lived_session
)
test_postgres_postcommit_notice_and_proof_delivery = (
    postcommit_notifications.test_notice_delivery_failure_is_optional_but_proof_delivery_still_propagates
)
test_postgres_postcommit_activation_cleanup_failure = (
    postcommit_notifications.test_mfa_activation_returns_usable_recovery_codes_when_throttle_cleanup_fails
)
test_postgres_postcommit_security_cleanup_failure = (
    postcommit_notifications.test_completed_security_change_survives_optional_throttle_cleanup_failure
)
test_postgres_precommit_cleanup_failure_remains_closed = (
    postcommit_notifications.test_precommit_throttle_failure_still_rejects_without_issuing_session
)


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


@pytest.mark.parametrize("damage", ["deleted_tail", "signature", "root_hash"])
def test_postgres_runtime_checks_superseded_checkpoint_evidence(app, settings, _postgres_cluster, damage):
    """Historical verification joins run with the real append-only grants."""
    database = app.state.database
    service = app.state.audit_checkpoint_service
    for _ in range(2):
        with database.session_factory() as db:
            row = AuditEvent(event_type="test.pg.history", outcome="success", details_json="{}")
            with append_lock(db):
                seal_event(db, row, app.state.audit_key)
                db.add(row)
                db.commit()
            old = service.anchor(db)
            old_id, old_event_id = old.id, old.last_event_id
    # Simulate a SQL attacker through the isolated fixture's schema owner,
    # never by weakening the actual runtime grants under test.
    owner_url = _postgres_cluster.administrative_url.set(database=make_url(settings.database_url).database)
    owner = Database(owner_url.render_as_string(hide_password=False))
    try:
        with owner.session_factory() as db:
            if damage == "deleted_tail":
                db.delete(db.get(AuditEvent, old_event_id))
            else:
                setattr(db.get(AuditCheckpoint, old_id), damage, "f" * 64)
            db.commit()
    finally:
        owner.engine.dispose()
    with database.session_factory() as db:
        row = AuditEvent(event_type="test.pg.history.new", outcome="success", details_json="{}")
        with append_lock(db):
            seal_event(db, row, app.state.audit_key)
            db.add(row)
            db.commit()
        checkpoint_id = str(uuid.uuid4())
        payload = canonical_checkpoint(
            checkpoint_id=checkpoint_id, last_event_id=row.id,
            root_hash=row.entry_hash, created_at=row.created_at,
        )
        # Model a valid checkpoint from an older app which already superseded
        # the damage; current anchoring must refuse to conceal it further.
        db.add(AuditCheckpoint(
            id=checkpoint_id, last_event_id=row.id, root_hash=row.entry_hash,
            signature=sign_checkpoint(service.key, payload), created_at=row.created_at,
            signer_uri="hmac-sha256://scap/audit-checkpoint-v1", signer_version="v1",
            delivered_at=row.created_at, external_receipt="sha256:" + "a" * 64,
        ))
        db.commit()
        assert verify_chain(db, app.state.audit_key).intact
        verdict = service.verify_latest(db)
        assert not verdict.intact and not verdict.fully_anchored
        assert verdict.failed_checkpoint_id == old_id
        assert verdict.failed_checkpoint_event_id == old_event_id
        with pytest.raises(AuditCheckpointError):
            service.anchor(db)


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
