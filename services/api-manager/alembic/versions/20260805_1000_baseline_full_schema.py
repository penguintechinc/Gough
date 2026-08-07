"""Baseline migration: full schema from ORM models.

Revision ID: 20260805_1000_baseline
Revises:
Create Date: 2026-08-05 10:00:00.000000

Gough has never gone to production -- there is no migrated database whose
history must be preserved. This migration replaces the entire prior chain
(which had drifted from the ORM models and never applied cleanly against a
fresh database -- missing/renamed tables, wrong FK targets, an unusably
short alembic_version.version_num column, a literal-string database name in
a GRANT statement) with a single baseline that builds the schema directly
from app.models_sqlalchemy.Base (which app.models_m1 registers all M1 tables
onto) and app.db.init_db.Base. This guarantees model/migration parity by
construction: every column type, default, and index is exactly what the
models declare, including the dialect-guarded constructs already present in
the models (nodes.hardware_tags JSONB+GIN, joiner_secrets partial indexes,
webhook_endpoints JSONB) -- so this migration is portable across PostgreSQL,
MySQL/MariaDB Galera, and SQLite the same way the models already are.

Three tables are used at runtime via penguin-dal but have no SQLAlchemy
model in either Base (pre-existing gap, not introduced here -- see
tests/pg_fixtures.py's module docstring): ``vault_bootstrap_tokens``,
``alert_rules``, ``upgrade_runs``. Their DDL is carried over verbatim from
the migrations that used to create them so those tables keep being created;
giving them proper models is a follow-up, not done here.

Also carries over, verbatim in intent, four PostgreSQL views, five DB roles
with grants, and row-level-security policies that were previously created by
dedicated migrations -- none of this is representable in SQLAlchemy
metadata, so it runs as raw postgres-only ``op.execute()`` calls after the
model-driven ``create_all()``. The database-name GRANT bug (a literal
"current_database" identifier instead of the actual database name) is fixed
here rather than carried over.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260805_1000_baseline'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Build the full schema from ORM models, plus modelless tables/views/roles/RLS."""
    # Widen alembic_version.version_num up front. Alembic hardcodes this
    # column as VARCHAR(32); this revision's own id fits, but a future
    # descriptively-named revision easily won't (several previously did).
    # SQLite has no enforced VARCHAR length, so this is a no-op there.
    if op.get_bind().dialect.name != 'sqlite':
        op.alter_column(
            'alembic_version',
            'version_num',
            existing_type=sa.String(32),
            type_=sa.String(255),
        )

    import sys
    import types
    from pathlib import Path

    # app.models_m1 does `from .models_sqlalchemy import Base` -- a relative
    # import that only resolves if models_m1 is loaded as part of the "app"
    # package, so a bare `import models_m1` (the pattern env.py itself uses
    # for models_sqlalchemy) doesn't work here. But the real `app/__init__.py`
    # is the Quart application factory (imports Quart, penguin_aaa, wires
    # middleware, ...) -- entirely inappropriate to execute as a side effect
    # of a migration, and importing it here also triggers a real bug: env.py
    # already put app/ itself on sys.path, and once werkzeug does its own
    # `import secrets`, Python resolves that to app/secrets/ (a package in
    # this codebase) instead of the stdlib module, since app/ is directly on
    # sys.path. Register a lightweight stand-in "app" package instead --
    # skips app/__init__.py's body entirely while still making
    # `app.models_sqlalchemy` / `app.models_m1` / `app.db.init_db` resolve as
    # genuine submodules (relative imports and all), matching how
    # tests/pg_fixtures.py imports these same three names.
    service_root = Path(__file__).resolve().parent.parent.parent
    app_dir = service_root / "app"
    if "app" not in sys.modules:
        app_pkg = types.ModuleType("app")
        app_pkg.__path__ = [str(app_dir)]
        sys.modules["app"] = app_pkg
    if str(service_root) not in sys.path:
        sys.path.insert(0, str(service_root))

    from app.models_sqlalchemy import Base as MainBase
    # Importing models_m1 registers its classes (nodes, biomes,
    # node_egg_assignments, deployments, joiner_secrets, audit_events,
    # migration_events, migration_policy, leader_leases, dr_drills,
    # slo_definitions, node_bmc, hardware_firmware, node_tags_operator,
    # spiffe_trust_entries, storage_backends, disks, disk_plans, node_events,
    # webhook_endpoints, ...) onto MainBase.metadata -- it shares MainBase
    # rather than declaring its own (see app.models_sqlalchemy.create_all_tables,
    # which does the same import for exactly this reason).
    from app import models_m1  # noqa: F401
    from app.db.init_db import Base as InitBase

    bind = op.get_bind()
    MainBase.metadata.create_all(bind=bind, checkfirst=True)
    InitBase.metadata.create_all(bind=bind, checkfirst=True)

    dialect = bind.dialect.name

    # --- Modelless tables (pre-existing gap; DDL carried over verbatim from
    # 20260430_1100_plan4_security / 20260509_1000_create_upgrade_runs_table) ---
    op.create_table(
        "vault_bootstrap_tokens",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("node_id", sa.Integer(), nullable=True),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["node_id"], ["nodes.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vault_bootstrap_tokens_node_id", "vault_bootstrap_tokens", ["node_id"])
    op.create_index("ix_vault_bootstrap_tokens_expires_at", "vault_bootstrap_tokens", ["expires_at"])

    op.create_table(
        "alert_rules",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("metric_name", sa.Text(), nullable=False),
        sa.Column("threshold", sa.Numeric(), nullable=False),
        sa.Column("duration_seconds", sa.Integer(), nullable=False, server_default=sa.literal(60)),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    op.create_table(
        "upgrade_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("biome_id", sa.Integer, sa.ForeignKey("biomes.id"), nullable=False),
        sa.Column("target_version", sa.String(50), nullable=False),
        sa.Column("cluster_id", sa.String(100), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("phase", sa.String(50), nullable=False, server_default="canary"),
        sa.Column("nodes_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("nodes_completed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("nodes_failed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rollback_reason", sa.Text, nullable=True),
        sa.Column("actor_sub", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_upgrade_runs_biome_id", "upgrade_runs", ["biome_id"])
    op.create_index("ix_upgrade_runs_status", "upgrade_runs", ["status"])
    op.create_index("ix_upgrade_runs_cluster_id", "upgrade_runs", ["cluster_id"])

    if dialect != 'postgresql':
        return

    # --- Postgres-only views (webui-ro role), carried over from
    # 20260427_2000_create_views_and_redactions ---
    op.execute("""
        CREATE VIEW v_nodes_public AS
        SELECT id, tenant_id, name, state, dmi_uuid, primary_nic_mac,
               ipv4, ipv6, hardware_tags, posture, discovered_at, deployed_at
        FROM nodes
    """)
    op.execute("""
        CREATE VIEW v_eggs_public AS
        SELECT id, name, display_name, description, version,
               egg_kind, phase, workload_type, lock_to_host,
               requires_hardware_tags, prefers_hardware_tags,
               forbids_hardware_tags, signing_key_id, sbom_url,
               is_active, is_default, created_at, updated_at
        FROM biomes
    """)
    op.execute("""
        CREATE VIEW v_capacity_public AS
        SELECT n.id AS node_id, n.tenant_id, n.name, n.state
        FROM nodes n
        WHERE n.state IN ('ready', 'draining', 'quarantined')
    """)
    op.execute("""
        CREATE VIEW v_audit_events_redacted AS
        SELECT id, ts, cluster_id, tenant_id, actor_sub, action,
               resource_kind, resource_id, request_id
        FROM audit_events
    """)

    # --- Per-service DB roles + grants, carried over from
    # 20260427_2030_create_db_roles_and_grants, fixing the literal
    # "current_database" identifier bug (GRANT ON DATABASE takes a literal
    # identifier, not an expression -- must look the name up and interpolate
    # it) and dropping the dangling "egg_groups" grant (no migration or model
    # anywhere ever created that table). ---
    db_name = bind.execute(sa.text('SELECT current_database()')).scalar()

    for role in ("api-manager-rw", "worker-ipxe-rw", "webui-ro", "audit-reader", "migration-runner"):
        op.execute(f'CREATE ROLE "{role}" WITH LOGIN')
    for role in ("api-manager-rw", "worker-ipxe-rw", "webui-ro", "audit-reader", "migration-runner"):
        op.execute(f'GRANT CONNECT ON DATABASE "{db_name}" TO "{role}"')
    for role in ("api-manager-rw", "worker-ipxe-rw", "webui-ro", "audit-reader", "migration-runner"):
        op.execute(f'GRANT USAGE ON SCHEMA public TO "{role}"')

    m1_tables = ['nodes', 'disks', 'disk_plans', 'node_egg_assignments', 'biomes',
                 'storage_backends', 'migration_events', 'migration_policy',
                 'joiner_secrets', 'node_bmc', 'hardware_firmware', 'spiffe_trust_entries',
                 'leader_leases', 'dr_drills', 'slo_definitions', 'node_tags_operator']
    for tbl in m1_tables:
        op.execute(f'GRANT SELECT, INSERT, UPDATE ON {tbl} TO "api-manager-rw"')
    op.execute('GRANT SELECT, INSERT ON audit_events TO "api-manager-rw"')
    op.execute('GRANT DELETE ON node_egg_assignments TO "api-manager-rw"')
    op.execute('GRANT DELETE ON migration_events TO "api-manager-rw"')
    op.execute('GRANT DELETE ON disk_plans TO "api-manager-rw"')
    # biomes: app.api.biomes.delete_biome's hard-delete path
    # (``db(db.biomes.id == biome_id).delete()``) needs DELETE in addition to
    # the SELECT/INSERT/UPDATE the m1_tables loop above already grants.
    op.execute('GRANT DELETE ON biomes TO "api-manager-rw"')
    # webhook_endpoints (app.models_m1.WebhookEndpoint) was simply left out
    # of the m1_tables list above, even though app.api.webhooks runs under
    # this same role in production (Config.DB_USER) -- same gap class as
    # audit_events/biomes. UPDATE is required too: the penguin-dal-converted
    # delete_webhook/create_webhook/list_webhooks/test_webhook handlers don't
    # currently issue UPDATEs, but webhook_endpoints has an updated_at column
    # future writers will need, and there's no reason this role should be
    # missing the one DML verb the m1_tables loop grants everyone else.
    op.execute('GRANT SELECT, INSERT, UPDATE, DELETE ON webhook_endpoints TO "api-manager-rw"')

    op.execute('GRANT SELECT ON nodes TO "worker-ipxe-rw"')
    op.execute('GRANT SELECT ON node_egg_assignments TO "worker-ipxe-rw"')
    op.execute('GRANT SELECT ON biomes TO "worker-ipxe-rw"')
    op.execute('GRANT SELECT ON spiffe_trust_entries TO "worker-ipxe-rw"')
    op.execute('GRANT INSERT ON audit_events TO "worker-ipxe-rw"')

    op.execute('GRANT SELECT ON v_nodes_public TO "webui-ro"')
    op.execute('GRANT SELECT ON v_eggs_public TO "webui-ro"')
    op.execute('GRANT SELECT ON v_capacity_public TO "webui-ro"')
    op.execute('GRANT SELECT ON v_audit_events_redacted TO "webui-ro"')

    op.execute('GRANT SELECT ON audit_events TO "audit-reader"')
    op.execute(
        'GRANT SELECT (id, cluster_id, tenant_id, biome_kind, scope, ttl_seconds, '
        'expires_at, rotation_class, created_at, rotated_at, revoked_at) '
        'ON joiner_secrets TO "audit-reader"'
    )

    op.execute(f'GRANT ALL ON DATABASE "{db_name}" TO "migration-runner"')

    # --- Row-level security (tenant isolation), carried over from
    # 20260427_2030_create_db_roles_and_grants. migration_policy is
    # excluded -- unlike every other table here, app.models_m1.MigrationPolicy
    # has no tenant_id column (it's cluster-scoped, keyed by a unique
    # cluster_id, not tenant-scoped), so a tenant_isolation policy referencing
    # tenant_id would reference a column that doesn't exist.
    rls_tables = ['nodes', 'disks', 'disk_plans', 'node_egg_assignments', 'biomes',
                  'storage_backends', 'migration_events',
                  'joiner_secrets', 'audit_events', 'dr_drills', 'slo_definitions',
                  'hardware_firmware', 'node_tags_operator', 'node_bmc',
                  'webhook_endpoints']
    for tbl in rls_tables:
        op.execute(f'ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY')
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {tbl}
            USING (current_setting('app.current_tenant', true) IN (tenant_id, '__default__', '__all__'))
        """)

    # node_events has its own bespoke RLS policy (distinct name and USING
    # clause, allowing a '__super__' override), carried over from
    # 20260429_0900_node_events -- it was intentionally never part of the
    # generic rls_tables loop above.
    op.execute('ALTER TABLE node_events ENABLE ROW LEVEL SECURITY')
    op.execute("""
        CREATE POLICY node_events_tenant_isolation
          ON node_events
          USING (
            tenant_id = current_setting('app.current_tenant', true)
            OR current_setting('app.current_tenant', true) = '__super__'
          )
    """)


def downgrade() -> None:
    """Not supported for the baseline -- drop and recreate the schema/database instead."""
    raise NotImplementedError(
        "Downgrading past the baseline is not supported. Drop and recreate "
        "the schema/database instead."
    )
