"""Create disk_plans table (Wave 2a Task #7).

Revision ID: 20260427_1030_disk_plans
Revises: 20260427_1000_disks
Create Date: 2026-04-27 10:30:00.000000

Part of Sprint 1 Wave 2a infrastructure expansion. Introduces the disk_plans table
per the Data Model Extensions section. Disk plans describe partitioning, filesystem
type, mount points, RAID levels, and encryption for disks belonging to nodes.

References:
- Spec: Data Model Extensions (disk_plans table)
- Spec: Partitioning & Mount Planning (mount_point, size_bytes, partition_index)
- Spec: Filesystem Support (fs_type: ext4|xfs|btrfs|swap|raw)
- Spec: RAID & Encryption (raid_level, encryption: none|luks)
- Spec: Remaining-Disk Allocation (size_bytes=0 means remaining capacity)
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260427_1030_disk_plans'
down_revision = '20260427_1000_disks'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create disk_plans table with dual FK to nodes and disks, indexes, and uniqueness.

    Portable across PostgreSQL, MySQL/MariaDB Galera, and SQLite via SQLAlchemy
    column types. Cascading delete on node or disk removal.
    """
    op.create_table(
        'disk_plans',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('node_id', sa.Integer, nullable=False),
        sa.Column('disk_id', sa.Integer, nullable=False),
        sa.Column('tenant_id', sa.String(255), nullable=False, server_default='__default__'),
        sa.Column('mount_point', sa.String(255), nullable=False),
        sa.Column('size_bytes', sa.BigInteger, nullable=False),
        sa.Column('fs_type', sa.String(16), nullable=False),
        sa.Column('partition_index', sa.Integer, nullable=False),
        sa.Column('raid_level', sa.String(8), nullable=True),
        sa.Column('encryption', sa.String(8), nullable=False, server_default='none'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['node_id'], ['nodes.id'], ondelete='CASCADE', name='fk_disk_plans_node_id'),
        sa.ForeignKeyConstraint(['disk_id'], ['disks.id'], ondelete='CASCADE', name='fk_disk_plans_disk_id'),
        sa.UniqueConstraint('node_id', 'mount_point', name='uq_disk_plans_node_mount_point'),
    )

    op.create_index('ix_disk_plans_node_id', 'disk_plans', ['node_id'])
    op.create_index('ix_disk_plans_disk_id', 'disk_plans', ['disk_id'])
    op.create_index('ix_disk_plans_tenant_id', 'disk_plans', ['tenant_id'])


def downgrade() -> None:
    """Drop disk_plans table."""
    op.drop_table('disk_plans')
