"""Create node_egg_assignments table (Wave 2a Task #8).

Revision ID: 20260427_1130_node_egg_assignments
Revises: 20260427_1030_disk_plans
Create Date: 2026-04-27 11:30:00.000000

Part of Sprint 1 Wave 2a infrastructure expansion. Introduces the node_egg_assignments
table per the Data Model Extensions and Egg Instance Lifecycle sections. Tracks assignment
of egg instances to nodes with status tracking, dependency coordination, and readiness probes.

References:
- Spec: Data Model Extensions (node_egg_assignments table)
- Spec: Egg Instance Lifecycle (phase: phase1_helper|phase2_initial|post_deploy|always)
- Spec: Egg Instance Lifecycle (status: pending|deploying|ready|failed|migrating|upgrading|draining|removed)
- Spec: Egg Dependency Graph deep-dive (depends_on_egg_instance_id for cross-node coordination)
- Spec: Readiness Probes (readiness_probe_state: not_started|probing|passed|failed)
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260427_1130_node_egg_assignments'
down_revision = '20260427_1030_disk_plans'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create node_egg_assignments table with FKs to nodes, eggs, and self-referential FK for deps.

    Portable across PostgreSQL, MySQL/MariaDB Galera, and SQLite via SQLAlchemy
    column types. One assignment per egg per node enforced by unique constraint.
    """
    op.create_table(
        'node_egg_assignments',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('node_id', sa.Integer, nullable=False),
        sa.Column('egg_id', sa.Integer, nullable=False),
        sa.Column('tenant_id', sa.String(255), nullable=False, server_default='__default__'),
        sa.Column('phase', sa.String(32), nullable=False),
        sa.Column('status', sa.String(32), nullable=False, server_default='pending'),
        sa.Column('depends_on_egg_instance_id', sa.Integer, nullable=True),
        sa.Column('readiness_probe_state', sa.String(32), nullable=False, server_default='not_started'),
        sa.Column('last_event_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('assigned_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('deployed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('removed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['node_id'], ['nodes.id'], ondelete='CASCADE', name='fk_node_egg_assignments_node_id'),
        sa.ForeignKeyConstraint(['egg_id'], ['eggs.id'], ondelete='RESTRICT', name='fk_node_egg_assignments_egg_id'),
        sa.ForeignKeyConstraint(['depends_on_egg_instance_id'], ['node_egg_assignments.id'], ondelete='SET NULL', name='fk_node_egg_assignments_depends_on'),
        sa.UniqueConstraint('node_id', 'egg_id', name='uq_node_egg_assignments_node_egg'),
    )

    op.create_index('ix_node_egg_assignments_node_id', 'node_egg_assignments', ['node_id'])
    op.create_index('ix_node_egg_assignments_egg_id', 'node_egg_assignments', ['egg_id'])
    op.create_index('ix_node_egg_assignments_status', 'node_egg_assignments', ['status'])
    op.create_index('ix_node_egg_assignments_tenant_id', 'node_egg_assignments', ['tenant_id'])
    op.create_index('ix_node_egg_assignments_phase', 'node_egg_assignments', ['phase'])


def downgrade() -> None:
    """Drop node_egg_assignments table."""
    op.drop_table('node_egg_assignments')
