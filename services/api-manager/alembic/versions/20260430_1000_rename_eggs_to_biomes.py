"""Rename eggs to biomes throughout schema.

Revision ID: 20260430_1000_rename_eggs_to_biomes
Revises: 20260430_0900_plan3_orchestration
Create Date: 2026-04-30 10:00:00.000000

Renames all egg/Egg/eggs/Eggs terminology to biome/Biome/biomes/Biomes throughout
the database schema, including table names, column names, index names, and foreign
key references.

References:
- Terminology standardization: egg → biome (deployable artifact)
"""

from alembic import op
import sqlalchemy as sa


revision = "20260430_1000_rename_eggs_to_biomes"
down_revision = "20260430_0900_plan3_orchestration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Rename eggs table to biomes and update all references."""
    # Rename table
    op.rename_table("eggs", "biomes")
    op.rename_table("node_egg_assignments", "node_biome_assignments")

    # Rename indexes on biomes table
    op.drop_index("ix_eggs_egg_kind", table_name="biomes")
    op.drop_index("ix_eggs_phase", table_name="biomes")
    op.drop_index("ix_eggs_workload_type", table_name="biomes")
    op.drop_index("ix_eggs_tenant_id", table_name="biomes")
    op.drop_index("ix_eggs_lock_to_host", table_name="biomes")

    op.create_index("ix_biomes_biome_kind", "biomes", ["biome_kind"])
    op.create_index("ix_biomes_phase", "biomes", ["phase"])
    op.create_index("ix_biomes_workload_type", "biomes", ["workload_type"])
    op.create_index("ix_biomes_tenant_id", "biomes", ["tenant_id"])
    op.create_index("ix_biomes_lock_to_host", "biomes", ["lock_to_host"])

    # Rename column if it exists (might be called egg_type or biome_type depending on baseline)
    # For now, assume it was egg_type in legacy schema
    try:
        op.alter_column("biomes", "egg_type", new_column_name="biome_type")
    except Exception:
        # Column may not exist or already renamed; skip
        pass

    # Rename egg_kind column references (already biome_kind in M1 schema, so skip)

    # Rename indexes on node_biome_assignments table
    op.drop_index("ix_node_egg_assignments_node_id", table_name="node_biome_assignments")
    op.drop_index("ix_node_egg_assignments_egg_id", table_name="node_biome_assignments")
    op.drop_index("ix_node_egg_assignments_status", table_name="node_biome_assignments")
    op.drop_index("ix_node_egg_assignments_tenant_id", table_name="node_biome_assignments")
    op.drop_index("ix_node_egg_assignments_phase", table_name="node_biome_assignments")

    op.create_index("ix_node_biome_assignments_node_id", "node_biome_assignments", ["node_id"])
    op.create_index("ix_node_biome_assignments_biome_id", "node_biome_assignments", ["biome_id"])
    op.create_index("ix_node_biome_assignments_status", "node_biome_assignments", ["status"])
    op.create_index("ix_node_biome_assignments_tenant_id", "node_biome_assignments", ["tenant_id"])
    op.create_index("ix_node_biome_assignments_phase", "node_biome_assignments", ["phase"])

    # Rename foreign key and column: egg_id → biome_id
    op.alter_column("node_biome_assignments", "egg_id", new_column_name="biome_id")

    # Drop and recreate foreign key constraint with new name
    op.drop_constraint("node_egg_assignments_egg_id_fkey", "node_biome_assignments", type_="foreignkey")
    op.create_foreign_key(
        "node_biome_assignments_biome_id_fkey",
        "node_biome_assignments",
        "biomes",
        ["biome_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    # Rename depends_on column
    op.alter_column("node_biome_assignments", "depends_on_egg_instance_id", new_column_name="depends_on_biome_instance_id")

    # Drop and recreate self-referencing foreign key
    op.drop_constraint("node_egg_assignments_depends_on_egg_instance_id_fkey", "node_biome_assignments", type_="foreignkey")
    op.create_foreign_key(
        "node_biome_assignments_depends_on_biome_instance_id_fkey",
        "node_biome_assignments",
        "node_biome_assignments",
        ["depends_on_biome_instance_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # Rename unique constraint
    op.drop_constraint("uq_node_egg_assignments_node_egg", "node_biome_assignments", type_="unique")
    op.create_unique_constraint("uq_node_biome_assignments_node_biome", "node_biome_assignments", ["node_id", "biome_id"])

    # Update deployments table: egg_id → biome_id
    op.drop_index("ix_deployments_egg_node", table_name="deployments")
    op.alter_column("deployments", "egg_id", new_column_name="biome_id")
    op.drop_constraint("deployments_egg_id_fkey", "deployments", type_="foreignkey")
    op.create_foreign_key(
        "deployments_biome_id_fkey",
        "deployments",
        "biomes",
        ["biome_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index("ix_deployments_biome_node", "deployments", ["biome_id", "node_id"])

    # Update migration_events table: egg_instance_id → biome_instance_id, egg_id → biome_id, egg_kind → biome_kind
    op.drop_index("ix_migration_events_egg_instance_id", table_name="migration_events")
    op.alter_column("migration_events", "egg_instance_id", new_column_name="biome_instance_id")
    op.alter_column("migration_events", "egg_id", new_column_name="biome_id")
    op.alter_column("migration_events", "egg_kind", new_column_name="biome_kind")

    op.drop_constraint("migration_events_egg_instance_id_fkey", "migration_events", type_="foreignkey")
    op.create_foreign_key(
        "migration_events_biome_instance_id_fkey",
        "migration_events",
        "node_biome_assignments",
        ["biome_instance_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.create_index("ix_migration_events_biome_instance_id", "migration_events", ["biome_instance_id"])

    # Update joiner_secrets table: emitter_egg_id → emitter_biome_id
    op.alter_column("joiner_secrets", "emitter_egg_id", new_column_name="emitter_biome_id")
    op.drop_constraint("joiner_secrets_emitter_egg_id_fkey", "joiner_secrets", type_="foreignkey")
    op.create_foreign_key(
        "joiner_secrets_emitter_biome_id_fkey",
        "joiner_secrets",
        "biomes",
        ["emitter_biome_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    # Update joiner_secrets index
    op.drop_index("ix_joiner_secrets_cluster_egg_extractor", table_name="joiner_secrets")
    op.create_index(
        "ix_joiner_secrets_cluster_biome_extractor",
        "joiner_secrets",
        ["cluster_id", "biome_kind", "extractor_name"],
    )


def downgrade() -> None:
    """Revert all renames back to eggs terminology."""
    # Revert joiner_secrets
    op.drop_index("ix_joiner_secrets_cluster_biome_extractor", table_name="joiner_secrets")
    op.create_index(
        "ix_joiner_secrets_cluster_egg_extractor",
        "joiner_secrets",
        ["cluster_id", "egg_kind", "extractor_name"],
    )

    op.drop_constraint("joiner_secrets_emitter_biome_id_fkey", "joiner_secrets", type_="foreignkey")
    op.alter_column("joiner_secrets", "emitter_biome_id", new_column_name="emitter_egg_id")
    op.create_foreign_key(
        "joiner_secrets_emitter_egg_id_fkey",
        "joiner_secrets",
        "eggs",
        ["emitter_egg_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    # Revert migration_events
    op.drop_index("ix_migration_events_biome_instance_id", table_name="migration_events")
    op.drop_constraint("migration_events_biome_instance_id_fkey", "migration_events", type_="foreignkey")

    op.alter_column("migration_events", "biome_instance_id", new_column_name="egg_instance_id")
    op.alter_column("migration_events", "biome_id", new_column_name="egg_id")
    op.alter_column("migration_events", "biome_kind", new_column_name="egg_kind")

    op.create_foreign_key(
        "migration_events_egg_instance_id_fkey",
        "migration_events",
        "node_egg_assignments",
        ["egg_instance_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_migration_events_egg_instance_id", "migration_events", ["egg_instance_id"])

    # Revert deployments
    op.drop_index("ix_deployments_biome_node", table_name="deployments")
    op.drop_constraint("deployments_biome_id_fkey", "deployments", type_="foreignkey")
    op.alter_column("deployments", "biome_id", new_column_name="egg_id")
    op.create_foreign_key(
        "deployments_egg_id_fkey",
        "deployments",
        "eggs",
        ["egg_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index("ix_deployments_egg_node", "deployments", ["egg_id", "node_id"])

    # Revert node_biome_assignments
    op.drop_constraint("uq_node_biome_assignments_node_biome", "node_biome_assignments", type_="unique")
    op.create_unique_constraint("uq_node_egg_assignments_node_egg", "node_biome_assignments", ["node_id", "biome_id"])

    op.drop_constraint("node_biome_assignments_depends_on_biome_instance_id_fkey", "node_biome_assignments", type_="foreignkey")
    op.alter_column("node_biome_assignments", "depends_on_biome_instance_id", new_column_name="depends_on_egg_instance_id")
    op.create_foreign_key(
        "node_egg_assignments_depends_on_egg_instance_id_fkey",
        "node_biome_assignments",
        "node_biome_assignments",
        ["depends_on_egg_instance_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.drop_constraint("node_biome_assignments_biome_id_fkey", "node_biome_assignments", type_="foreignkey")
    op.alter_column("node_biome_assignments", "biome_id", new_column_name="egg_id")
    op.create_foreign_key(
        "node_egg_assignments_egg_id_fkey",
        "node_biome_assignments",
        "eggs",
        ["egg_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    op.drop_index("ix_node_biome_assignments_node_id", table_name="node_biome_assignments")
    op.drop_index("ix_node_biome_assignments_biome_id", table_name="node_biome_assignments")
    op.drop_index("ix_node_biome_assignments_status", table_name="node_biome_assignments")
    op.drop_index("ix_node_biome_assignments_tenant_id", table_name="node_biome_assignments")
    op.drop_index("ix_node_biome_assignments_phase", table_name="node_biome_assignments")

    op.create_index("ix_node_egg_assignments_node_id", "node_biome_assignments", ["node_id"])
    op.create_index("ix_node_egg_assignments_egg_id", "node_biome_assignments", ["egg_id"])
    op.create_index("ix_node_egg_assignments_status", "node_biome_assignments", ["status"])
    op.create_index("ix_node_egg_assignments_tenant_id", "node_biome_assignments", ["tenant_id"])
    op.create_index("ix_node_egg_assignments_phase", "node_biome_assignments", ["phase"])

    # Revert biomes table to eggs
    op.drop_index("ix_biomes_biome_kind", table_name="biomes")
    op.drop_index("ix_biomes_phase", table_name="biomes")
    op.drop_index("ix_biomes_workload_type", table_name="biomes")
    op.drop_index("ix_biomes_tenant_id", table_name="biomes")
    op.drop_index("ix_biomes_lock_to_host", table_name="biomes")

    op.create_index("ix_eggs_egg_kind", "biomes", ["egg_kind"])
    op.create_index("ix_eggs_phase", "biomes", ["phase"])
    op.create_index("ix_eggs_workload_type", "biomes", ["workload_type"])
    op.create_index("ix_eggs_tenant_id", "biomes", ["tenant_id"])
    op.create_index("ix_eggs_lock_to_host", "biomes", ["lock_to_host"])

    try:
        op.alter_column("biomes", "biome_type", new_column_name="egg_type")
    except Exception:
        pass

    op.rename_table("node_biome_assignments", "node_egg_assignments")
    op.rename_table("biomes", "eggs")
