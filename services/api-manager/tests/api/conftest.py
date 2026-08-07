"""Pytest fixtures for API endpoint tests.

Provides a Quart test client with blueprints registered and auth stubbed.
"""

import importlib
import uuid
from types import SimpleNamespace

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
