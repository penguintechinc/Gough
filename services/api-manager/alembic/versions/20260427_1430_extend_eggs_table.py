"""Extend eggs table with deployment, packaging, and workload management columns (Wave 2b-A Task #1).

Revision ID: 20260427_1430_eggs_extensions
Revises: 20260427_1400_spiffe_trust_entries
Create Date: 2026-04-27 14:30:00.000000

Part of Sprint 1 Wave 2b-A eggs table extensions. Adds columns for egg classification,
deployment lifecycle phases, container/VM selection, node affinity, cluster auto-join,
upgrade strategy, storage/hardware requirements, joiner secret orchestration, snapshots,
and network interface specifications.

References:
- Spec: Egg Model (Full Specification) → egg_kind (infrastructure|k8s|monitoring|storage|user_workload|custom)
- Spec: Egg Model → phase (phase1_helper|phase2_initial|post_deploy|always)
- Spec: Egg Model → workload_type (lxc|vm)
- Spec: Egg Model → lock_to_host, auto_join_cluster, upgrade_strategy (rolling|canary|blue_green)
- Spec: Egg Model → storage_requirements_json, readiness_probe (per endpoint spec)
- Spec: Egg Model → signing_key_id, sbom_url, registry_url for supply chain
- Spec: Egg Model → requires|prefers|forbids hardware tags for node affinity
- Spec: Egg Model → joiner secret emission and consumption specs
- Spec: Egg Model → snapshot_schedule_json, required_interfaces
- Spec: Tenant-Scoped Multi-Tenancy → tenant_id forward-compatibility
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260427_1430_eggs_extensions'
down_revision = '20260427_1400_spiffe_trust_entries'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add 21 columns to eggs table for deployment, packaging, and workload orchestration.

    Portable across PostgreSQL, MySQL/MariaDB Galera, and SQLite via SQLAlchemy
    column types. All columns have appropriate defaults for backward compatibility.
    """
    op.add_column('eggs', sa.Column('egg_kind', sa.String(32), nullable=False, server_default='custom'))
    op.add_column('eggs', sa.Column('phase', sa.String(32), nullable=False, server_default='post_deploy'))
    op.add_column('eggs', sa.Column('workload_type', sa.String(8), nullable=False, server_default='lxc'))
    op.add_column('eggs', sa.Column('lock_to_host', sa.Boolean, nullable=False, server_default='false'))
    op.add_column('eggs', sa.Column('auto_join_cluster', sa.Boolean, nullable=False, server_default='false'))
    op.add_column('eggs', sa.Column('upgrade_strategy', sa.String(16), nullable=False, server_default='rolling'))
    op.add_column('eggs', sa.Column('storage_requirements_json', sa.JSON(), nullable=True))
    op.add_column('eggs', sa.Column('readiness_probe', sa.JSON(), nullable=True))
    op.add_column('eggs', sa.Column('signing_key_id', sa.String(255), nullable=True))
    op.add_column('eggs', sa.Column('sbom_url', sa.String(1024), nullable=True))
    op.add_column('eggs', sa.Column('registry_url', sa.String(1024), nullable=True))
    op.add_column('eggs', sa.Column('requires_hardware_tags', sa.JSON(), nullable=True))
    op.add_column('eggs', sa.Column('prefers_hardware_tags', sa.JSON(), nullable=True))
    op.add_column('eggs', sa.Column('forbids_hardware_tags', sa.JSON(), nullable=True))
    op.add_column('eggs', sa.Column('emits_joiner_secrets', sa.Boolean, nullable=False, server_default='false'))
    op.add_column('eggs', sa.Column('joiner_emit_spec', sa.JSON(), nullable=True))
    op.add_column('eggs', sa.Column('consumes_joiner_secrets_from', sa.JSON(), nullable=True))
    op.add_column('eggs', sa.Column('joiner_consume_spec', sa.JSON(), nullable=True))
    op.add_column('eggs', sa.Column('snapshot_schedule_json', sa.JSON(), nullable=True))
    op.add_column('eggs', sa.Column('required_interfaces', sa.JSON(), nullable=True))
    op.add_column('eggs', sa.Column('tenant_id', sa.String(255), nullable=False, server_default='__default__'))

    # Create indexes on high-cardinality and filter-heavy columns
    op.create_index('ix_eggs_egg_kind', 'eggs', ['egg_kind'])
    op.create_index('ix_eggs_phase', 'eggs', ['phase'])
    op.create_index('ix_eggs_workload_type', 'eggs', ['workload_type'])
    op.create_index('ix_eggs_tenant_id', 'eggs', ['tenant_id'])
    op.create_index('ix_eggs_lock_to_host', 'eggs', ['lock_to_host'])


def downgrade() -> None:
    """Drop 21 columns and associated indexes from eggs table."""
    op.drop_index('ix_eggs_lock_to_host', table_name='eggs')
    op.drop_index('ix_eggs_tenant_id', table_name='eggs')
    op.drop_index('ix_eggs_workload_type', table_name='eggs')
    op.drop_index('ix_eggs_phase', table_name='eggs')
    op.drop_index('ix_eggs_egg_kind', table_name='eggs')

    op.drop_column('eggs', 'tenant_id')
    op.drop_column('eggs', 'required_interfaces')
    op.drop_column('eggs', 'snapshot_schedule_json')
    op.drop_column('eggs', 'joiner_consume_spec')
    op.drop_column('eggs', 'consumes_joiner_secrets_from')
    op.drop_column('eggs', 'joiner_emit_spec')
    op.drop_column('eggs', 'emits_joiner_secrets')
    op.drop_column('eggs', 'forbids_hardware_tags')
    op.drop_column('eggs', 'prefers_hardware_tags')
    op.drop_column('eggs', 'requires_hardware_tags')
    op.drop_column('eggs', 'registry_url')
    op.drop_column('eggs', 'sbom_url')
    op.drop_column('eggs', 'signing_key_id')
    op.drop_column('eggs', 'readiness_probe')
    op.drop_column('eggs', 'storage_requirements_json')
    op.drop_column('eggs', 'upgrade_strategy')
    op.drop_column('eggs', 'auto_join_cluster')
    op.drop_column('eggs', 'lock_to_host')
    op.drop_column('eggs', 'workload_type')
    op.drop_column('eggs', 'phase')
    op.drop_column('eggs', 'egg_kind')
