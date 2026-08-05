"""Create nodes table (Wave 2a Task #7).

Revision ID: 20260427_0930_nodes
Revises: 20260424_0900_baseline
Create Date: 2026-04-27 09:30:00.000000

Part of Sprint 1 Wave 2a infrastructure expansion. Introduces the nodes table
per the Data Model Extensions section (bare-metal node inventory, state machine,
hardware discovery). This table is the root for disks and disk_plans hierarchy.

References:
- Spec: Data Model Extensions (nodes table)
- Spec: State Machine (node state values: new, probed, planned, deploying, etc.)
- Spec: Hardware Discovery & Attestation (dmi_uuid, mac_addr, hardware_json, tags)
- Spec: Node Posture & Compliance (posture field: compliant|noncompliant)
- Spec: Address Family Preference (preferred_addr_family)
- CQ-1: Forward compatibility with multi-tenant (tenant_id default '__default__')
- CQ-4: Node attestation method selection (discovery_agent|operator_attested)
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '20260427_0930_nodes'
down_revision = '20260424_0900_baseline'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create nodes table with state machine, indexes, and uniqueness constraints.

    Portable across PostgreSQL, MySQL/MariaDB Galera, and SQLite via SQLAlchemy
    column types and dialect-aware index creation.
    """
    op.create_table(
        'nodes',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('tenant_id', sa.String(255), nullable=False, server_default='__default__'),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('state', sa.String(32), nullable=False, server_default='new'),
        sa.Column('dmi_uuid', sa.String(64), nullable=True),
        sa.Column('primary_nic_mac', sa.String(17), nullable=True),
        sa.Column('ipv4', sa.String(15), nullable=True),
        sa.Column('ipv6', sa.String(45), nullable=True),
        sa.Column('boot_config_id', sa.Integer, nullable=True),
        sa.Column('hardware_json', sa.JSON(), nullable=True),
        sa.Column(
            'hardware_tags',
            sa.JSON().with_variant(postgresql.JSONB(), 'postgresql'),
            nullable=True,
        ),
        sa.Column('posture', sa.String(32), nullable=False, server_default='compliant'),
        sa.Column('preferred_addr_family', sa.String(16), nullable=False, server_default='auto'),
        sa.Column('attestation_method', sa.String(32), nullable=False, server_default='discovery_agent'),
        sa.Column('discovered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('deployed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint('tenant_id', 'name', name='uq_nodes_tenant_name'),
        sa.UniqueConstraint('tenant_id', 'dmi_uuid', name='uq_nodes_tenant_dmi_uuid'),
    )

    op.create_index('ix_nodes_state', 'nodes', ['state'])
    op.create_index('ix_nodes_tenant_id', 'nodes', ['tenant_id'])
    op.create_index('ix_nodes_primary_nic_mac', 'nodes', ['primary_nic_mac'])

    # PostgreSQL-specific GIN index for hardware_tags JSONB. GIN has no MySQL/MariaDB
    # or SQLite equivalent for JSON columns, so this index is a Postgres-only perf
    # optimization -- skipped (not substituted) on other dialects, matching the
    # column type itself (JSONB on Postgres, plain JSON elsewhere via with_variant).
    if op.get_bind().dialect.name == 'postgresql':
        op.create_index(
            'ix_nodes_hardware_tags',
            'nodes',
            ['hardware_tags'],
            postgresql_using='gin',
        )


def downgrade() -> None:
    """Drop nodes table."""
    op.drop_table('nodes')
