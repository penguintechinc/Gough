"""Create storage_backends table (Wave 2a Task #8).

Revision ID: 20260427_1200_storage_backends
Revises: 20260427_1130_node_egg_assignments
Create Date: 2026-04-27 12:00:00.000000

Part of Sprint 1 Wave 2a infrastructure expansion. Introduces the storage_backends table
per the Storage Backend Selection section. Manages distributed storage backend configuration,
health status, and capacity tracking across Nest, Longhorn, Ceph, iSCSI, NFS, local, and S3.

References:
- Spec: Storage Backend Selection (kind: nest|longhorn|ceph|iscsi|nfs|local|s3)
- Spec: Storage Backend Selection (is_default, config_json, credentials_ref for Vault)
- Spec: Storage Backend Selection (status: initializing|healthy|degraded|failed|draining)
- Spec: Storage Backend Selection (capacity_total_bytes, capacity_used_bytes)
- Spec: Storage Backend Selection (health_check_at for monitoring)
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260427_1200_storage_backends'
down_revision = '20260427_1130_node_egg_assignments'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create storage_backends table with per-cluster backend config, health, and capacity.

    Portable across PostgreSQL, MySQL/MariaDB Galera, and SQLite via SQLAlchemy
    column types. Backend names unique per cluster. Credentials stored as Vault path refs.
    """
    op.create_table(
        'storage_backends',
        sa.Column('id', sa.Uuid(), nullable=False, primary_key=True),
        sa.Column('cluster_id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.String(255), nullable=False, server_default='__default__'),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('is_default', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('config_json', sa.JSON(), nullable=True),
        sa.Column('credentials_ref', sa.String(255), nullable=True),
        sa.Column('status', sa.String(16), nullable=False, server_default='initializing'),
        sa.Column('capacity_total_bytes', sa.BigInteger, nullable=True),
        sa.Column('capacity_used_bytes', sa.BigInteger, nullable=True),
        sa.Column('health_check_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint('cluster_id', 'name', name='uq_storage_backends_cluster_name'),
    )

    op.create_index('ix_storage_backends_cluster_id', 'storage_backends', ['cluster_id'])
    op.create_index('ix_storage_backends_kind', 'storage_backends', ['kind'])
    op.create_index('ix_storage_backends_tenant_id', 'storage_backends', ['tenant_id'])
    op.create_index('ix_storage_backends_is_default', 'storage_backends', ['is_default'])


def downgrade() -> None:
    """Drop storage_backends table."""
    op.drop_table('storage_backends')
