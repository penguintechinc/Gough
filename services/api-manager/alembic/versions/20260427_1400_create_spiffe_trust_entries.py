"""Create spiffe_trust_entries table (Wave 2a Task #8).

Revision ID: 20260427_1400_spiffe_trust_entries
Revises: 20260427_1200_storage_backends
Create Date: 2026-04-27 14:00:00.000000

Part of Sprint 1 Wave 2a infrastructure expansion. Introduces the spiffe_trust_entries table
per the Security section's SPIFFE Trust Fabric. Manages workload identities, trust domains,
and federation entries for mTLS service-to-service authentication across control plane,
workers, nodes, eggs, and disaster recovery sites.

References:
- Spec: Security → SPIFFE Trust Fabric (spiffe_id format and uniqueness)
- Spec: Security → SPIFFE Trust Fabric (workload_class: control-plane-service|worker-leader|worker-replica|node-helper|node-permanent|egg-instance|dr-site)
- Spec: Security → SPIFFE Trust Fabric (trust_domain per cluster)
- Spec: Security → SPIFFE Trust Fabric (parent_spiffe_id for federation)
- Spec: Security → SPIFFE Trust Fabric (selectors JSON for workload attestation)
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260427_1400_spiffe_trust_entries'
down_revision = '20260427_1200_storage_backends'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create spiffe_trust_entries table with workload identity, federation, and attestation config.

    Portable across PostgreSQL, MySQL/MariaDB Galera, and SQLite via SQLAlchemy
    column types. SPIFFE IDs globally unique per trust domain.
    """
    op.create_table(
        'spiffe_trust_entries',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('spiffe_id', sa.String(512), nullable=False, unique=True),
        sa.Column('workload_class', sa.String(32), nullable=False),
        sa.Column('trust_domain', sa.String(255), nullable=False),
        sa.Column('parent_spiffe_id', sa.String(512), nullable=True),
        sa.Column('selectors', sa.JSON(), nullable=True),
        sa.Column('ttl_seconds', sa.Integer, nullable=False, server_default='3600'),
        sa.Column('active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_index('ix_spiffe_trust_entries_workload_class', 'spiffe_trust_entries', ['workload_class'])
    op.create_index('ix_spiffe_trust_entries_trust_domain', 'spiffe_trust_entries', ['trust_domain'])
    op.create_index('ix_spiffe_trust_entries_active', 'spiffe_trust_entries', ['active'])


def downgrade() -> None:
    """Drop spiffe_trust_entries table."""
    op.drop_table('spiffe_trust_entries')
