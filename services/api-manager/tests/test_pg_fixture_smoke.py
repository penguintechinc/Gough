"""Smoke test for the real-Postgres pytest fixture (tests/pg_fixtures.py).

Confirms the fixture is bound to real Postgres (not sqlite) and that the
schema built from both SQLAlchemy declarative bases actually landed --
including the M1 tables that only register onto ``Base.metadata`` via the
``app.models_m1`` side-effect import.

``pg_db`` needs no import here: conftest.py registers ``tests.pg_fixtures``
as a pytest plugin, so it (and ``pg_url``) are available to every test module
under ``tests/`` -- this is the pattern later conversion tasks should use.
"""


def test_pg_db_is_real_postgres(pg_db):
    assert pg_db.executesql("SELECT 1") == [(1,)]
    # A table defined directly on models_sqlalchemy.Base.
    assert "auth_user" in pg_db.tables
    # M1 tables, registered onto the SAME Base via the models_m1 import --
    # these are the ones that silently disappear if that import is dropped.
    assert "nodes" in pg_db.tables
    assert "leader_leases" in pg_db.tables
    assert "joiner_secrets" in pg_db.tables
    assert "audit_events" in pg_db.tables
    # A table from the second, unrelated init_db.Base.
    assert "api_definitions" in pg_db.tables
