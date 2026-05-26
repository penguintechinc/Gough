"""Create disks table (Wave 2a Task #7).

Revision ID: 20260427_1000_disks
Revises: 20260427_0930_nodes
Create Date: 2026-04-27 10:00:00.000000

Part of Sprint 1 Wave 2a infrastructure expansion. Introduces the disks table
per the Data Model Extensions section. Disks belong to a node and track
device inventory, SMART status, capacity, and assignment to storage backends.

References:
- Spec: Data Model Extensions (disks table)
- Spec: Storage Backend Integration (storage_backend: nest|longhorn|ceph|iscsi)
- Spec: Disk Tier Classification (tier: fast|bulk)
- Spec: SMART Health Monitoring (smart_status, smart_attributes_json)
- Spec: Dark Drive Concept (reserved_for_storage flag)
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260427_1000_disks'
down_revision = '20260427_0930_nodes'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create disks table with FK to nodes, indexes, and uniqueness constraints.

    Portable across PostgreSQL, MySQL/MariaDB Galera, and SQLite via SQLAlchemy
    column types. Cascading delete on node removal.
    """
    op.create_table(
        'disks',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('node_id', sa.Integer, nullable=False),
        sa.Column('tenant_id', sa.String(255), nullable=False, server_default='__default__'),
        sa.Column('device_path', sa.String(255), nullable=False),
        sa.Column('serial', sa.String(64), nullable=True),
        sa.Column('capacity_bytes', sa.BigInteger, nullable=False),
        sa.Column('rotational', sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column('smart_status', sa.String(16), nullable=False, server_default='unknown'),
        sa.Column('smart_attributes_json', sa.JSON(), nullable=True),
        sa.Column('reserved_for_storage', sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column('storage_backend', sa.String(32), nullable=True),
        sa.Column('tier', sa.String(16), nullable=False, server_default='bulk'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['node_id'], ['nodes.id'], ondelete='CASCADE', name='fk_disks_node_id'),
        sa.UniqueConstraint('node_id', 'device_path', name='uq_disks_node_device_path'),
    )

    op.create_index('ix_disks_node_id', 'disks', ['node_id'])
    op.create_index('ix_disks_tenant_id', 'disks', ['tenant_id'])
    op.create_index('ix_disks_serial', 'disks', ['serial'])
    op.create_index('ix_disks_storage_backend', 'disks', ['storage_backend'])


def downgrade() -> None:
    """Drop disks table."""
    op.drop_table('disks')
