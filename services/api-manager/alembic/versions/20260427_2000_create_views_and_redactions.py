"""Create redacted views for webui-ro role.

Revision ID: 20260427_2000_views_and_redactions
Revises: 20260427_1930_slo_definitions
Create Date: 2026-04-27 20:00:00.000000

"""
from alembic import op

revision = '20260427_2000_views_and_redactions'
down_revision = '20260427_1930_slo_definitions'
branch_labels = None
depends_on = None


def upgrade() -> None:
    dialect = op.get_bind().dialect
    if dialect.name == 'postgresql':
        op.execute("""
            CREATE VIEW v_nodes_public AS
            SELECT id, tenant_id, name, state, dmi_uuid, primary_nic_mac,
                   ipv4, ipv6, hardware_tags, posture, discovered_at, deployed_at
            FROM nodes
        """)
        op.execute("""
            CREATE VIEW v_eggs_public AS
            SELECT id, name, display_name, description, egg_type, version,
                   egg_kind, phase, workload_type, lock_to_host,
                   requires_hardware_tags, prefers_hardware_tags,
                   forbids_hardware_tags, signing_key_id, sbom_url,
                   is_active, is_default, created_at, updated_at
            FROM eggs
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


def downgrade() -> None:
    dialect = op.get_bind().dialect
    if dialect.name == 'postgresql':
        op.execute("DROP VIEW IF EXISTS v_audit_events_redacted")
        op.execute("DROP VIEW IF EXISTS v_capacity_public")
        op.execute("DROP VIEW IF EXISTS v_eggs_public")
        op.execute("DROP VIEW IF EXISTS v_nodes_public")
