"""Create node_bmc table for baseboard management controller configuration (Wave 2b-A Task #1).

Revision ID: 20260427_1500_node_bmc
Revises: 20260427_1430_eggs_extensions
Create Date: 2026-04-27 15:00:00.000000

Part of Sprint 1 Wave 2b-A hardware management expansion. Introduces the node_bmc table
per the Hardware Management → BMC section. Manages out-of-band access, credential references,
firmware summaries, and security detection (default credentials) for node lifecycle operations,
disaster recovery, and power management.

References:
- Spec: Hardware Management → BMC (protocol: redfish|ipmi2|ssh_clp)
- Spec: Hardware Management → BMC (endpoint, username_ref/password_ref via Vault)
- Spec: Hardware Management → BMC (cert_fingerprint SHA-256 validation)
- Spec: Hardware Management → BMC (session_ttl_sec, last_used_at for lifecycle)
- Spec: Hardware Management → BMC (capabilities, firmware_summary JSON)
- Spec: Hardware Management → BMC (factory_creds_detected triggers gough.bmc.default_credentials alert)
- Spec: Tenant-Scoped Multi-Tenancy → tenant_id per node for RBAC enforcement
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260427_1500_node_bmc'
down_revision = '20260427_1430_eggs_extensions'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create node_bmc table with BMC endpoint, credential refs, and operational state.

    Portable across PostgreSQL, MySQL/MariaDB Galera, and SQLite via SQLAlchemy
    column types. node_id is PK (one BMC per node), FK to nodes.id with CASCADE delete.
    """
    op.create_table(
        'node_bmc',
        sa.Column('node_id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('tenant_id', sa.String(255), nullable=False, server_default='__default__'),
        sa.Column('protocol', sa.String(16), nullable=False),
        sa.Column('endpoint', sa.String(255), nullable=False),
        sa.Column('username_ref', sa.String(255), nullable=False),
        sa.Column('password_ref', sa.String(255), nullable=False),
        sa.Column('cert_fingerprint', sa.String(95), nullable=True),
        sa.Column('session_ttl_sec', sa.Integer, nullable=False, server_default='1800'),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('capabilities', sa.JSON(), nullable=True),
        sa.Column('firmware_summary', sa.JSON(), nullable=True),
        sa.Column('factory_creds_detected', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['node_id'], ['nodes.id'], ondelete='CASCADE', name='fk_node_bmc_node_id'),
    )

    op.create_index('ix_node_bmc_tenant_id', 'node_bmc', ['tenant_id'])
    op.create_index('ix_node_bmc_protocol', 'node_bmc', ['protocol'])


def downgrade() -> None:
    """Drop node_bmc table and associated indexes."""
    op.drop_index('ix_node_bmc_protocol', table_name='node_bmc')
    op.drop_index('ix_node_bmc_tenant_id', table_name='node_bmc')
    op.drop_table('node_bmc')
