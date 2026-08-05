"""Real-Postgres test fixtures.

Reuses ``$DATABASE_URL`` when present (CI service container); otherwise spins
an ephemeral ``postgres:16-bookworm`` container via testcontainers for the
duration of the pytest session.

Schema is built from BOTH SQLAlchemy declarative bases used by this service:

* ``app.models_sqlalchemy.Base`` -- the main app models. Importing
  ``app.models_m1`` additionally registers the M1 sprint tables (``nodes``,
  ``leader_leases``, ``joiner_secrets``, ``audit_events``, ...) onto this
  SAME ``Base.metadata`` object -- ``models_m1`` does not declare its own
  Base, it just needs to be imported for its classes to register (see
  ``app.models_sqlalchemy.create_all_tables``, which does the same import
  for exactly this reason).
* ``app.db.init_db.Base`` -- a second, unrelated declarative base holding
  ``api_definitions`` / ``api_usage`` / ``api_keys``.

Known gap: three tables used at runtime via penguin-dal have no SQLAlchemy
model in either base -- they exist only as raw ``op.create_table()`` calls in
Alembic migrations, so ``Base.metadata.create_all()`` cannot create them:

* ``vault_bootstrap_tokens`` (alembic/versions/20260430_1100_plan4_security.py)
* ``alert_rules`` (alembic/versions/20260430_1100_plan4_security.py)
* ``upgrade_runs`` (alembic/versions/20260509_1000_create_upgrade_runs_table.py)
  -- actively read/written via ``db.upgrade_runs`` in ``app/api/biomes.py``.

Four Postgres views (``v_nodes_public``, ``v_eggs_public``,
``v_capacity_public``, ``v_audit_events_redacted``) and the per-service DB
roles/grants are likewise Alembic-only (raw ``op.execute()`` DDL) and are not
recreated here. See task-3-report.md for the full breakdown. Tests that need
any of the above should extend ``pg_db`` locally (e.g. via ``pg_url`` +
raw DDL) until a follow-up task decides how to fold them in -- do not assume
they exist on ``pg_db`` yet.

Pre-existing schema bug worked around here (NOT fixed at the source -- out of
this fixture's scope, see task-3-report.md): ``models_m1.Node.hardware_tags``
is a plain ``JSON`` column with a plain btree index
(``ix_nodes_hardware_tags``). Postgres' ``json`` type has no default btree
operator class, so ``CREATE INDEX`` -- and therefore the entire
``Base.metadata.create_all()`` call -- fails outright on real Postgres (SQLite
never caught this because it has no real type/operator-class system). This
same bug would hit ``app.models_sqlalchemy.create_all_tables()`` in a real
deployment, not just this fixture. ``pg_db`` skips creating that one index
(table + all other indexes/tables are created normally) so schema setup can
proceed; needs a real fix (e.g. ``JSONB`` + GIN, or drop the index) in
``app/models_m1.py`` under its own task.
"""

import os

import pytest


@pytest.fixture(scope="session")
def pg_url():
    """Session-scoped Postgres connection URL (``postgresql://...``).

    Reuses ``$DATABASE_URL`` when set (CI service container). Otherwise spins
    an ephemeral ``postgres:16-bookworm`` container via testcontainers, kept
    alive for the whole test session and torn down at the end.
    """
    existing = os.getenv("DATABASE_URL")
    if existing:
        yield existing.replace("postgresql+psycopg2://", "postgresql://")
        return

    from testcontainers.postgres import PostgresContainer

    with PostgresContainer("postgres:16-bookworm") as pg:
        yield pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")


@pytest.fixture
def pg_db(pg_url):
    """Function-scoped penguin-dal ``DB`` bound to a real Postgres instance.

    Wipes and rebuilds the ``public`` schema from both SQLAlchemy declarative
    bases (see module docstring for the known-missing-tables gap) before
    handing back a reflected penguin-dal ``DB``.
    """
    from sqlalchemy import create_engine, text

    from penguin_dal import DB

    from app.models_sqlalchemy import Base as MainBase

    # Import registers the M1 classes (nodes, leader_leases, joiner_secrets,
    # audit_events, ...) onto MainBase.metadata -- it shares MainBase rather
    # than declaring its own. Side-effect import only; noqa for the unused
    # name.
    from app import models_m1  # noqa: F401
    from app.db.init_db import Base as InitBase

    eng = create_engine(pg_url)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))

    # See module docstring: ix_nodes_hardware_tags is a btree index on a JSON
    # column, which Postgres rejects outright. Drop it from the metadata for
    # the duration of create_all() only, then restore it so the rest of the
    # process (other tests importing the same Base) still see the model as
    # declared in app/models_m1.py.
    nodes_table = MainBase.metadata.tables.get("nodes")
    skipped_index = None
    if nodes_table is not None:
        for idx in nodes_table.indexes:
            if idx.name == "ix_nodes_hardware_tags":
                skipped_index = idx
                break
        if skipped_index is not None:
            nodes_table.indexes.discard(skipped_index)

    try:
        MainBase.metadata.create_all(eng)  # schema authority = SQLAlchemy
    finally:
        if skipped_index is not None:
            nodes_table.indexes.add(skipped_index)

    InitBase.metadata.create_all(eng)
    eng.dispose()

    db = DB(pg_url, pool_size=2, reflect=True)
    yield db
    db.close()
