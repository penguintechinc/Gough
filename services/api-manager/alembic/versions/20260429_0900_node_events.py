"""Create node_events table for progress events from discovery agent and cloud-init.

Revision ID: 20260429_0900_node_events
Revises: 20260428_0900_bootstrap_nonces
Create Date: 2026-04-29 09:00:00.000000

Stores structured progress events POSTed by the discovery agent and
cloud-init runcmd steps via ``POST /api/v1/nodes/{id}/events``.
api-manager republishes each row to NATS subject ``gough.node.{id}.events``.

RLS policy:
  Tenant isolation via ``app.current_tenant`` GUC — each read is scoped to
  the tenant set by the middleware.
"""

from alembic import op
import sqlalchemy as sa


revision = "20260429_0900_node_events"
down_revision = "20260428_0900_bootstrap_nonces"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "node_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "node_id",
            sa.Integer(),
            sa.ForeignKey("nodes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(255), nullable=False, server_default="__default__"),
        sa.Column(
            "ts",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("stage", sa.String(255), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("progress_pct", sa.Integer(), nullable=True),
        sa.Column(
            "sequence_id",
            sa.BigInteger(),
            nullable=True,
            comment="Client-side sequence ID for resume/gap detection",
        ),
        sa.Column("raw_json", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    op.create_index("ix_node_events_node_id", "node_events", ["node_id"])
    op.create_index("ix_node_events_tenant_id", "node_events", ["tenant_id"])
    op.create_index("ix_node_events_ts", "node_events", ["ts"])
    op.create_index("ix_node_events_stage", "node_events", ["stage"])

    # Row-Level Security policy (PostgreSQL only).
    # Guard with a try/except so SQLite CI runs don't break.
    try:
        op.execute(
            "ALTER TABLE node_events ENABLE ROW LEVEL SECURITY"
        )
        op.execute(
            """
            CREATE POLICY node_events_tenant_isolation
              ON node_events
              USING (
                tenant_id = current_setting('app.current_tenant', true)
                OR current_setting('app.current_tenant', true) = '__super__'
              )
            """
        )
    except Exception:  # noqa: BLE001 — SQLite or non-PG environment
        pass


def downgrade() -> None:
    try:
        op.execute("DROP POLICY IF EXISTS node_events_tenant_isolation ON node_events")
    except Exception:  # noqa: BLE001
        pass

    op.drop_index("ix_node_events_stage", table_name="node_events")
    op.drop_index("ix_node_events_ts", table_name="node_events")
    op.drop_index("ix_node_events_tenant_id", table_name="node_events")
    op.drop_index("ix_node_events_node_id", table_name="node_events")
    op.drop_table("node_events")
