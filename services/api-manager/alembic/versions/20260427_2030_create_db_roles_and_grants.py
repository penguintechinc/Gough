"""Create DB roles, grants, and RLS policies per Security.

Revision ID: 20260427_2030_db_roles_and_grants
Revises: 20260427_2000_views_and_redactions
Create Date: 2026-04-27 20:30:00.000000

"""
from alembic import op

revision = '20260427_2030_db_roles_and_grants'
down_revision = '20260427_2000_views_and_redactions'
branch_labels = None
depends_on = None


def upgrade() -> None:
    dialect = op.get_bind().dialect
    if dialect.name != 'postgresql':
        return

    # Create roles
    op.execute('CREATE ROLE "api-manager-rw" WITH LOGIN')
    op.execute('CREATE ROLE "worker-ipxe-rw" WITH LOGIN')
    op.execute('CREATE ROLE "webui-ro" WITH LOGIN')
    op.execute('CREATE ROLE "audit-reader" WITH LOGIN')
    op.execute('CREATE ROLE "migration-runner" WITH LOGIN')

    # Grant CONNECT and USAGE
    op.execute('GRANT CONNECT ON DATABASE current_database TO "api-manager-rw"')
    op.execute('GRANT CONNECT ON DATABASE current_database TO "worker-ipxe-rw"')
    op.execute('GRANT CONNECT ON DATABASE current_database TO "webui-ro"')
    op.execute('GRANT CONNECT ON DATABASE current_database TO "audit-reader"')
    op.execute('GRANT CONNECT ON DATABASE current_database TO "migration-runner"')
    op.execute('GRANT USAGE ON SCHEMA public TO "api-manager-rw"')
    op.execute('GRANT USAGE ON SCHEMA public TO "worker-ipxe-rw"')
    op.execute('GRANT USAGE ON SCHEMA public TO "webui-ro"')
    op.execute('GRANT USAGE ON SCHEMA public TO "audit-reader"')
    op.execute('GRANT USAGE ON SCHEMA public TO "migration-runner"')

    # api-manager-rw grants
    m1_tables = ['nodes', 'disks', 'disk_plans', 'node_egg_assignments', 'eggs',
                 'egg_groups', 'storage_backends', 'migration_events', 'migration_policy',
                 'joiner_secrets', 'node_bmc', 'hardware_firmware', 'spiffe_trust_entries',
                 'leader_leases', 'dr_drills', 'slo_definitions', 'node_tags_operator']
    for tbl in m1_tables:
        op.execute(f'GRANT SELECT, INSERT, UPDATE ON {tbl} TO "api-manager-rw"')
    op.execute('GRANT INSERT ON audit_events TO "api-manager-rw"')
    op.execute('GRANT DELETE ON node_egg_assignments TO "api-manager-rw"')
    op.execute('GRANT DELETE ON migration_events TO "api-manager-rw"')
    op.execute('GRANT DELETE ON disk_plans TO "api-manager-rw"')

    # worker-ipxe-rw grants
    op.execute('GRANT SELECT ON nodes TO "worker-ipxe-rw"')
    op.execute('GRANT SELECT ON node_egg_assignments TO "worker-ipxe-rw"')
    op.execute('GRANT SELECT ON eggs TO "worker-ipxe-rw"')
    op.execute('GRANT SELECT ON spiffe_trust_entries TO "worker-ipxe-rw"')
    op.execute('GRANT INSERT ON audit_events TO "worker-ipxe-rw"')

    # webui-ro grants
    op.execute('GRANT SELECT ON v_nodes_public TO "webui-ro"')
    op.execute('GRANT SELECT ON v_eggs_public TO "webui-ro"')
    op.execute('GRANT SELECT ON v_capacity_public TO "webui-ro"')
    op.execute('GRANT SELECT ON v_audit_events_redacted TO "webui-ro"')

    # audit-reader grants
    op.execute('GRANT SELECT ON audit_events TO "audit-reader"')
    op.execute('GRANT SELECT (id, cluster_id, tenant_id, egg_kind, scope, ttl_seconds, expires_at, rotation_class, created_at, rotated_at, revoked_at) ON joiner_secrets TO "audit-reader"')

    # migration-runner grants
    op.execute('GRANT ALL ON DATABASE current_database TO "migration-runner"')

    # Enable RLS on tenant-scoped tables
    rls_tables = ['nodes', 'disks', 'disk_plans', 'node_egg_assignments', 'eggs',
                  'storage_backends', 'migration_events', 'migration_policy',
                  'joiner_secrets', 'audit_events', 'dr_drills', 'slo_definitions',
                  'hardware_firmware', 'node_tags_operator', 'node_bmc']
    for tbl in rls_tables:
        op.execute(f'ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY')
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {tbl}
            USING (current_setting('app.current_tenant', true) IN (tenant_id, '__default__', '__all__'))
        """)


def downgrade() -> None:
    dialect = op.get_bind().dialect
    if dialect.name != 'postgresql':
        return

    rls_tables = ['nodes', 'disks', 'disk_plans', 'node_egg_assignments', 'eggs',
                  'storage_backends', 'migration_events', 'migration_policy',
                  'joiner_secrets', 'audit_events', 'dr_drills', 'slo_definitions',
                  'hardware_firmware', 'node_tags_operator', 'node_bmc']
    for tbl in rls_tables:
        op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON {tbl}')
        op.execute(f'ALTER TABLE {tbl} DISABLE ROW LEVEL SECURITY')

    op.execute('DROP ROLE IF EXISTS "migration-runner"')
    op.execute('DROP ROLE IF EXISTS "audit-reader"')
    op.execute('DROP ROLE IF EXISTS "webui-ro"')
    op.execute('DROP ROLE IF EXISTS "worker-ipxe-rw"')
    op.execute('DROP ROLE IF EXISTS "api-manager-rw"')
