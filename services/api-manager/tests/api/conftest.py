"""Pytest fixtures for API endpoint tests.

Provides a Quart test client with blueprints registered and auth stubbed.

Also provides ``real_auth_env`` (regression: gh-31): a NON-injecting client
that drives the genuine authentication middleware chain. Unlike ``client`` /
``app_with_auth`` (which pin ``g.current_user`` in a ``before_request`` hook and
never install the real middleware), ``real_auth_env`` installs the production
``wire_middleware`` chain and populates ``g.current_user`` ONLY via a real
``Authorization: Bearer`` token flowing through ``_credential_validation``.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import jwt
import pytest
from quart import Quart, g
from sqlalchemy import Column, String, Table


def _define_table_with_string_id(dal_db, name, *fields):
    """Like ``dal_db.define_table`` but with a VARCHAR(36) string ``id``
    primary key instead of penguin_dal's auto-added Integer autoincrement id.

    ``penguin_dal.field.Field``'s ``type_="id"`` shortcut is hardcoded to an
    Integer column with no way to override -- but the real physical schema
    for app-supplied-UUID tables (``migration_policy``, ``migration_events``;
    see ``app.models_m1.UUID``, VARCHAR(36)) has a string primary key with no
    default. On SQLite, an auto-added ``INTEGER PRIMARY KEY`` becomes a rowid
    alias that rejects a string id with ``datatype mismatch`` -- this builds
    the table via raw SQLAlchemy against the DB's own metadata/engine
    (mirroring what ``define_table`` does internally, minus the auto-id
    logic) so ``dal_db.<name>`` resolves normally via ``DB.__getattr__``.
    """
    if name in getattr(dal_db, "tables", []):
        return
    columns = [Column("id", String(36), primary_key=True)]
    columns.extend(field.to_sa_column() for field in fields)
    table = Table(name, dal_db.metadata, *columns)
    dal_db.metadata.create_all(dal_db.engine, tables=[table])


def _passthrough_decorator(*dargs, **dkwargs):
    """Stub for auth_required / require_scopes.

    Returns the decorated function unchanged, allowing tests to run without
    JWT validation.
    """
    # Pattern: @decorator or @decorator(args)
    if len(dargs) == 1 and callable(dargs[0]) and not dkwargs:
        # Direct decoration: @auth_required
        return dargs[0]
    # Parameterized decoration: @require_scopes("a", "b")
    def _wrap(fn):
        return fn
    return _wrap


@pytest.fixture()
def client(dal, monkeypatch):
    """Create a Quart test client with all API blueprints."""
    # Patch get_db in app.models before reloading blueprints
    import app.models as models_mod
    monkeypatch.setattr(models_mod, "get_db", lambda: dal)

    # Stub auth decorators before importing blueprints
    import app.middleware as mw_mod
    import app.security.scope_enforcement as scope_mod

    monkeypatch.setattr(mw_mod, "auth_required", _passthrough_decorator)
    monkeypatch.setattr(scope_mod, "require_scopes", _passthrough_decorator)

    # Add migration-related tables to the test DAL
    from penguin_dal import Field
    from datetime import datetime, timezone

    if "biomes" not in getattr(dal, "tables", []):
        dal.define_table(
            "biomes",
            Field("name", "string", notnull=True),
            Field("tenant_id", "string", default="__default__"),
            Field("biome_kind", "string", default="custom"),
            Field("lock_to_host", "boolean", default=False),
            Field("requires_hardware_tags", "json"),
            Field("storage_requirements_json", "json"),
            migrate=True,
        )
    # ``node_egg_assignments`` is the real, baseline-created table (gh-21:
    # ``node_biome_assignments`` was a phantom name that never existed).
    if "node_egg_assignments" not in getattr(dal, "tables", []):
        dal.define_table(
            "node_egg_assignments",
            Field("node_id", "integer", notnull=True),
            Field("egg_id", "integer", notnull=True),
            Field("tenant_id", "string", default="__default__"),
            Field("status", "string", default="pending"),
            migrate=True,
        )
    # ``id`` is app-supplied VARCHAR(36) UUID on the real table (see
    # app.api.migration.patch_migration_policy's ``id=str(uuid.uuid4())``)
    # -- use the string-id helper, not ``dal.define_table``'s auto Integer id.
    _define_table_with_string_id(
        dal,
        "migration_policy",
        Field("cluster_id", "string", notnull=True),
        Field("enabled", "boolean", default=False),
        Field("evaluation_interval_seconds", "integer", default=300),
        Field("min_healthy_nodes", "integer", default=3),
        Field("max_concurrent_migrations", "integer", default=1),
        Field("require_target_capacity_headroom_cpu_pct", "integer", default=20),
        Field("require_target_capacity_headroom_mem_pct", "integer", default=20),
        Field("require_target_capacity_headroom_disk_pct", "integer", default=15),
        Field("rollback_on_destination_failure", "boolean", default=True),
        Field("rollback_window_seconds", "integer", default=300),
        Field("forbid_migration_during_partition", "boolean", default=True),
        Field("forbid_migration_during_maintenance", "boolean", default=True),
        Field("waddleai_risk_threshold", "float", default=0.75),
        Field("capacity_forecast_horizon_days", "integer", default=7),
        Field("created_at", "datetime"),
        Field("updated_at", "datetime"),
    )
    # ``id`` is app-supplied VARCHAR(36) UUID on the real table (see
    # app.api.migration._record_safety_event's ``id=str(uuid.uuid4())``).
    _define_table_with_string_id(
        dal,
        "migration_events",
        Field("biome_instance_id", "integer"),
        Field("biome_id", "integer"),
        Field("biome_kind", "string"),
        Field("src_node_id", "integer"),
        Field("dst_node_id", "integer"),
        Field("reason", "string"),
        Field("result", "string"),
        Field("rejection_reason", "string"),
        Field("safety_check_details_json", "json"),
        Field("started_at", "datetime"),
        Field("completed_at", "datetime"),
        Field("duration_seconds", "float"),
    )

    # Seed nodes, biome, assignment, and policy for migration tests
    _now = datetime.now(timezone.utc)
    _node_id = dal.nodes.insert(
        tenant_id="default", name="node-1", state="ready",
        dmi_uuid="00000000-0000-0000-0000-000000000001",
        primary_nic_mac="aa:bb:cc:dd:ee:01",
    )
    # Second node as migration target
    dal.nodes.insert(
        tenant_id="default", name="node-2", state="ready",
        dmi_uuid="00000000-0000-0000-0000-000000000002",
        primary_nic_mac="aa:bb:cc:dd:ee:02",
    )
    _biome_id = dal.biomes.insert(
        name="test-biome", biome_kind="custom", lock_to_host=False,
    )
    # First insert gets id=1 in SQLite — used by POST trigger tests
    dal.node_egg_assignments.insert(
        node_id=int(_node_id), egg_id=int(_biome_id),
        tenant_id="default", status="active",
    )
    # Seed policy with min_healthy_nodes=1 to match single-node test cluster.
    # ``id`` is app-supplied VARCHAR(36) UUID -- no default (see
    # _define_table_with_string_id above).
    dal.migration_policy.insert(
        id=str(uuid.uuid4()),
        cluster_id="default",
        enabled=False,
        evaluation_interval_seconds=300,
        min_healthy_nodes=1,
        max_concurrent_migrations=1,
        require_target_capacity_headroom_cpu_pct=20,
        require_target_capacity_headroom_mem_pct=20,
        require_target_capacity_headroom_disk_pct=15,
        rollback_on_destination_failure=True,
        rollback_window_seconds=300,
        forbid_migration_during_partition=True,
        forbid_migration_during_maintenance=True,
        waddleai_risk_threshold=0.75,
        capacity_forecast_horizon_days=7,
        created_at=_now,
        updated_at=_now,
    )
    dal.commit()

    # Reload blueprints to pick up stubbed decorators
    import app.api.migration as migration_mod
    import app.api.clusters as clusters_mod
    import app.api.primary as primary_mod

    migration_mod = importlib.reload(migration_mod)
    monkeypatch.setattr(migration_mod, "get_db", lambda: dal)

    clusters_mod = importlib.reload(clusters_mod)
    monkeypatch.setattr(clusters_mod, "get_db", lambda: dal)

    primary_mod = importlib.reload(primary_mod)
    monkeypatch.setattr(primary_mod, "get_db", lambda: dal)

    app = Quart(__name__)
    app.config["TESTING"] = True
    app.config["CLUSTER_ID"] = "default"
    app.config["JWT_SECRET_KEY"] = "test-secret-key"
    app.url_map.strict_slashes = False

    app.register_blueprint(migration_mod.migration_bp, url_prefix="/api/v1/migration")
    app.register_blueprint(clusters_mod.clusters_bp, url_prefix="/api/v1/clusters")
    app.register_blueprint(primary_mod.primary_bp, url_prefix="/api/v1/primary")

    @app.before_request
    async def _inject_auth():
        """Stub authentication with default admin user."""
        g.current_user = {
            "id": 1,
            "username": "test-operator",
            "role": "admin",  # Full access for testing
            "_jwt_payload": {
                "sub": "test-operator",
                "tenant": "default",
                "scope": (
                    "gough.capacity.read gough.migration.policy "
                    "gough.migration.trigger gough.migration.override-lock "
                    "gough.storage.read gough.storage.configure "
                    "gough.cluster.read gough.cluster.admin gough.cluster.superadmin"
                ),
                "mfa": True,
            },
        }
        g.tenant_context = SimpleNamespace(tenant_id="default")
        g.mfa_verified = True  # Assume MFA for testing

    return app.test_client()


@pytest.fixture()
def app_with_auth(dal, monkeypatch):
    """Create a Quart app with biomes blueprint and auth stubbed.

    Returns the app instance (not test_client), allowing fixture to call
    app.test_client() multiple times if needed.
    """
    # Patch get_db to return the test DAL FIRST, before any imports
    import app.models as models_mod
    monkeypatch.setattr(models_mod, "get_db", lambda: dal)

    # Stub auth decorators
    import app.middleware as mw_mod
    import app.security.scope_enforcement as scope_mod

    monkeypatch.setattr(mw_mod, "auth_required", _passthrough_decorator)
    monkeypatch.setattr(scope_mod, "require_scopes", _passthrough_decorator)

    # Reload biomes blueprint to pick up stubbed decorators and patched get_db
    import app.api.biomes as biomes_mod
    import app.api.nodes as nodes_mod

    biomes_mod = importlib.reload(biomes_mod)
    nodes_mod = importlib.reload(nodes_mod)

    # Patch get_db for nodes module too
    monkeypatch.setattr(nodes_mod, "get_db", lambda: dal)

    app = Quart(__name__)
    app.config["TESTING"] = True
    app.config["CLUSTER_ID"] = "default"
    app.config["JWT_SECRET_KEY"] = "test-secret-key"
    app.url_map.strict_slashes = False

    app.register_blueprint(biomes_mod.biomes_bp)
    app.register_blueprint(nodes_mod.nodes_bp)

    @app.before_request
    async def _inject_auth():
        """Stub authentication with default admin user."""
        g.current_user = {
            "id": 1,
            "username": "test-operator",
            "role": "admin",  # Full access for testing
            "_jwt_payload": {
                "sub": "test-operator",
                "tenant": "__default__",
                "scope": (
                    "gough.biomes.read gough.biomes.create gough.biomes.write "
                    "gough.biomes.delete gough.biomes.sign gough.biomes.upgrade "
                    "gough.cluster.admin gough.cluster.superadmin"
                ),
                "mfa": True,
            },
        }
        g.tenant_context = SimpleNamespace(tenant_id="__default__")
        g.mfa_verified = True

    return app


@pytest.fixture()
def app(monkeypatch):
    """Bare Quart app with auth stubbed — used as base for blueprint-specific fixtures."""
    import app.middleware as mw_mod
    import app.security.scope_enforcement as scope_mod

    monkeypatch.setattr(mw_mod, "auth_required", _passthrough_decorator)
    monkeypatch.setattr(scope_mod, "require_scopes", _passthrough_decorator)

    # Stub decode_token and get_user_by_id so the real auth_required decorator
    # (already applied at import time to integrations_bp routes) passes through.
    _fake_jwt = {
        "type": "access",
        "sub": "1",
        "scope": (
            "gough.cluster.read gough.cluster.admin gough.cluster.superadmin "
            "gough.integrations.read gough.integrations.write gough.integrations.admin"
        ),
        "tenant": "default",
    }
    _fake_user = {
        "id": 1,
        "username": "test-operator",
        "role": "admin",
        "is_active": True,
    }
    monkeypatch.setattr(mw_mod, "decode_token", lambda token: _fake_jwt)
    monkeypatch.setattr(mw_mod, "get_user_by_id", lambda user_id: _fake_user)

    from quart import Quart, g

    quart_app = Quart(__name__)
    quart_app.config["TESTING"] = True
    quart_app.config["CLUSTER_ID"] = "default"
    quart_app.config["JWT_SECRET_KEY"] = "test-secret-key"
    quart_app.url_map.strict_slashes = False

    @quart_app.before_request
    async def _inject_auth():
        g.current_user = {
            "id": 1,
            "username": "test-operator",
            "role": "admin",
            "_jwt_payload": {
                "sub": "test-operator",
                "tenant": "default",
                "scope": (
                    "gough.integrations.read gough.integrations.write "
                    "gough.integrations.admin gough.cluster.superadmin"
                ),
                "mfa": True,
            },
        }
        g.tenant_context = SimpleNamespace(tenant_id="default")
        g.mfa_verified = True

    return quart_app


@pytest.fixture()
def dal_with_eggs(dal):
    """Alias for dal_with_biomes for backward-compat.

    Extends dal with biomes + node_egg_assignments tables.
    """
    from penguin_dal import Field

    # Define biomes table
    dal.define_table(
        "biomes",
        Field("tenant_id", "string", default="__default__"),
        Field("name", "string", notnull=True),
        Field("display_name", "string"),
        Field("description", "string"),
        Field("biome_type", "string"),
        Field("egg_type", "string"),
        Field("version", "string"),
        Field("category", "string"),
        Field("snap_name", "string"),
        Field("snap_channel", "string", default="stable"),
        Field("snap_classic", "boolean", default=False),
        Field("cloud_init_content", "text"),
        Field("lxd_image_alias", "string"),
        Field("lxd_image_url", "string"),
        Field("lxd_profiles", "json"),
        Field("is_hypervisor_config", "boolean", default=False),
        Field("dependencies", "json"),
        Field("min_ram_mb", "integer"),
        Field("min_disk_gb", "integer"),
        Field("required_architecture", "string", default="any"),
        Field("is_active", "boolean", default=True),
        Field("is_default", "boolean", default=False),
        Field("checksum", "string"),
        Field("size_bytes", "bigint"),
        # M1 extensions
        Field("biome_kind", "string", default="custom"),
        Field("phase", "string", default="post_deploy"),
        Field("workload_type", "string", default="lxc"),
        Field("lock_to_host", "boolean", default=False),
        Field("auto_join_cluster", "boolean", default=False),
        Field("upgrade_strategy", "string", default="rolling"),
        Field("requires_hardware_tags", "json"),
        Field("prefers_hardware_tags", "json"),
        Field("forbids_hardware_tags", "json"),
        Field("storage_requirements_json", "json"),
        Field("readiness_probe", "json"),
        Field("emits_joiner_secrets", "boolean", default=False),
        Field("joiner_emit_spec", "json"),
        Field("consumes_joiner_secrets_from", "json"),
        Field("joiner_consume_spec", "json"),
        Field("snapshot_schedule_json", "json"),
        Field("required_interfaces", "json"),
        Field("signing_key_id", "string"),
        Field("sbom_url", "string"),
        Field("registry_url", "string"),
        Field("signing_status", "string", default="unsigned"),
        Field("created_at", "datetime"),
        Field("updated_at", "datetime"),
        migrate=True,
    )

    # Define node_egg_assignments table (gh-21: the real, baseline-created
    # table -- ``node_biome_assignments`` was a phantom name that never
    # existed in production).
    dal.define_table(
        "node_egg_assignments",
        Field("node_id", "integer", notnull=True),
        Field("egg_id", "integer", notnull=True),
        Field("tenant_id", "string", default="__default__"),
        Field("status", "string", default="pending"),
        Field("annotation", "string"),
        Field("phase", "string", default="post_deploy"),
        Field("readiness_probe_state", "string", default="pending"),
        Field("depends_on_egg_instance_id", "integer"),
        Field("assigned_at", "datetime"),
        Field("deployed_at", "datetime"),
        Field("removed_at", "datetime"),
        Field("created_at", "datetime"),
        Field("updated_at", "datetime"),
        migrate=True,
    )

    return dal


# ============================================================================
# Real auth-chain fixture (regression: gh-31)
# ============================================================================
#
# The ``client`` / ``app_with_auth`` fixtures above deliberately pin
# ``g.current_user`` in a ``before_request`` hook and never call the real
# ``wire_middleware``. That is fine for exercising handler bodies, but it makes
# it impossible to test the authentication middleware itself: every request
# already has a principal, and the fail-closed scope layer that turns a missing
# principal into a 401 is not even installed. Any test that asserts "valid token
# is accepted" or "missing token is rejected" against that fixture is
# self-confirming -- the assertion is satisfied by the injector, not by the code
# under test.
#
# ``real_auth_env`` closes that gap. It installs the production middleware chain
# (``_credential_validation`` -> tenant -> ``_enforce_scopes``, in that order)
# and injects NOTHING. The one and only way ``g.current_user`` becomes non-None
# is a valid ``Authorization: Bearer <jwt>`` decoding to a seeded, ACTIVE user
# row -- exactly the production path.

SECRET_KEY: str = "gh31-real-auth-chain-secret-key-32b+"


@dataclass(slots=True)
class RealAuthEnv:
    """Non-injecting test client + a real HS256 token minter (regression: gh-31).

    ``mint()`` produces tokens with the same secret + algorithm that
    ``app.middleware.decode_token`` verifies, so a token issued here drives the
    genuine credential-validation -> scope-enforcement path.
    """

    client: Any
    user_id: int
    secret: str

    def mint(
        self,
        scope: str = "gough.nodes.read",
        *,
        sub: str | int | None = None,
        tenant: str | None = "default",
        user_id: int | None = None,
        expired: bool = False,
    ) -> str:
        """Mint an HS256 access token that ``decode_token`` will accept.

        ``sub`` defaults to the seeded user's id so ``get_user_by_id(int(sub))``
        resolves an ACTIVE row. ``tenant``/``scope`` feed the tenant + scope
        middleware. ``user_id`` (when set) additionally satisfies the auth
        blueprint's own ``require_auth`` decorator (which keys on ``user_id``).
        """
        issued = datetime.utcnow()
        exp = issued - timedelta(hours=1) if expired else issued + timedelta(hours=1)
        payload: dict[str, Any] = {
            "sub": str(self.user_id if sub is None else sub),
            "scope": scope,
            "type": "access",
            "iat": issued,
            "exp": exp,
        }
        if tenant is not None:
            payload["tenant"] = tenant
        if user_id is not None:
            payload["user_id"] = user_id
        return jwt.encode(payload, self.secret, algorithm="HS256")


@pytest.fixture()
def real_auth_env(tmp_path, monkeypatch):
    """Client that drives the REAL auth middleware chain (regression: gh-31).

    Registers the real ``nodes`` and ``auth`` blueprints, seeds an ACTIVE user +
    a node into a fresh sqlite DAL, and installs the production
    ``wire_middleware`` chain. Route decorators are reduced to passthroughs so
    the sole authenticator is ``_credential_validation`` -- ``g.current_user``
    is never pre-injected.
    """
    import app.auth as auth_mod
    import app.middleware as mw_mod
    import app.models as models_mod
    import app.security.scope_enforcement as scope_mod
    from app.security_datastore import PyDALUserDatastore
    from penguin_dal import DB, Field

    now = datetime.now(timezone.utc)
    db = DB(
        f"sqlite:///{tmp_path}/gh31-{os.getpid()}.db",
        pool_size=1,
        reflect=False,
        migrate=True,
    )

    # ``nodes`` -- note created_at/updated_at: list_nodes orders by them.
    db.define_table(
        "nodes",
        Field("tenant_id", "string", default="__default__"),
        Field("name", "string"),
        Field("state", "string", default="new"),
        Field("dmi_uuid", "string"),
        Field("primary_nic_mac", "string"),
        Field("hardware_tags", "json"),
        Field("hardware_json", "json"),
        Field("created_at", "datetime"),
        Field("updated_at", "datetime"),
        migrate=True,
    )
    # Identity tables (mirror app/models_sqlalchemy.py) so the REAL
    # get_user_by_id() / require_auth resolve a genuine row.
    db.define_table(
        "auth_role",
        Field("name", "string"),
        Field("description", "string"),
        Field("permissions", "text"),
        Field("created_at", "datetime"),
        migrate=True,
    )
    db.define_table(
        "auth_user",
        Field("email", "string"),
        Field("password", "string"),
        Field("active", "boolean", default=True),
        Field("fs_uniquifier", "string"),
        Field("confirmed_at", "datetime"),
        Field("last_login_at", "datetime"),
        Field("current_login_at", "datetime"),
        Field("last_login_ip", "string"),
        Field("current_login_ip", "string"),
        Field("login_count", "integer", default=0),
        Field("tf_totp_secret", "string"),
        Field("tf_primary_method", "string"),
        Field("full_name", "string"),
        Field("created_at", "datetime"),
        Field("updated_at", "datetime"),
        migrate=True,
    )
    db.define_table(
        "auth_user_roles",
        Field("user_id", "integer"),
        Field("role_id", "integer"),
        migrate=True,
    )
    db.define_table(
        "auth_refresh_tokens",
        Field("user_id", "integer"),
        Field("token_hash", "string"),
        Field("expires_at", "datetime"),
        Field("revoked", "boolean", default=False),
        Field("created_at", "datetime"),
        migrate=True,
    )
    db.define_table(
        "auth_password_resets",
        Field("user_id", "integer"),
        Field("token_hash", "string"),
        Field("expires_at", "datetime"),
        Field("used", "boolean", default=False),
        Field("created_at", "datetime"),
        migrate=True,
    )

    role_id = db.auth_role.insert(
        name="admin", description="", permissions="", created_at=now
    )
    user_id = int(
        db.auth_user.insert(
            email="operator@gough.test",
            password="not-used-by-these-tests",
            active=True,
            fs_uniquifier="gh31-uniquifier",
            full_name="GH31 Operator",
            login_count=0,
            created_at=now,
            updated_at=now,
        )
    )
    db.auth_user_roles.insert(user_id=user_id, role_id=int(role_id))
    db.nodes.insert(
        tenant_id="default",
        name="gh31-node",
        state="ready",
        dmi_uuid="00000000-0000-0000-0000-0000000000aa",
        primary_nic_mac="aa:bb:cc:dd:ee:aa",
        created_at=now,
        updated_at=now,
    )
    db.commit()

    # Route decorators -> passthrough so the ONLY code that can populate
    # g.current_user is the real _credential_validation before_request hook.
    monkeypatch.setattr(mw_mod, "auth_required", _passthrough_decorator)
    monkeypatch.setattr(scope_mod, "require_scopes", _passthrough_decorator)
    # Point every get_db() at the seeded DB.
    monkeypatch.setattr(models_mod, "get_db", lambda: db)
    monkeypatch.setattr(auth_mod, "get_db", lambda: db)
    # The auth blueprint's require_auth loads roles via user_datastore, whose
    # _get_user_roles uses pyDAL's ``.ALL`` selector -- unimplemented in
    # penguin_dal and unrelated to gh-31 (see task report). Stub ONLY that role
    # query so require_auth can build request.user; the auth decision itself
    # (token valid, user exists + active) stays entirely real.
    monkeypatch.setattr(PyDALUserDatastore, "_get_user_roles", lambda self, uid: [])

    import app.api.nodes as nodes_mod

    nodes_mod = importlib.reload(nodes_mod)
    monkeypatch.setattr(nodes_mod, "get_db", lambda: db)

    app = Quart(__name__)
    app.config["TESTING"] = True
    app.config["CLUSTER_ID"] = "default"
    app.config["JWT_SECRET_KEY"] = SECRET_KEY
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=7)
    app.config["db"] = db
    app.url_map.strict_slashes = False
    app.user_datastore = PyDALUserDatastore(db)

    app.register_blueprint(nodes_mod.nodes_bp)
    app.register_blueprint(auth_mod.auth_bp, url_prefix="/api/v1/auth")

    # Install the production middleware chain (credential validation -> tenant
    # -> scope enforcement), exactly as app/__init__.py's wire_middleware does.
    from app.middleware import wire_middleware

    asyncio.run(wire_middleware(app))

    env = RealAuthEnv(client=app.test_client(), user_id=user_id, secret=SECRET_KEY)
    try:
        yield env
    finally:
        try:
            db.close()
        except Exception:
            pass
