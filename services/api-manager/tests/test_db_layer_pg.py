"""Tests for the db/database.py + db/galera.py -> executesql migration.

``execute_query`` (app/db/database.py) is plain ANSI SQL, so it is exercised
against a real Postgres instance via the ``pg_db`` fixture (tests/pg_fixtures.py).

The Galera helpers in app/db/galera.py issue MariaDB/Galera-only SQL
(``SET SESSION wsrep_sync_wait``, ``SET SESSION auto_increment_*``,
``SHOW STATUS``) that cannot run against Postgres. Those are covered with
SQL-assertion unit tests instead: a mocked ``db`` (and, for the
multi-statement auto-increment helper, a mocked ``Tx`` returned by
``db.transaction()``) records the exact SQL string and placeholders passed to
``executesql``, and the test asserts on that call -- not on live WSREP
behavior.

``pg_db`` / ``pg_url`` need no import: conftest.py registers
``tests.pg_fixtures`` as a pytest plugin, so both fixtures are available to
every test module under ``tests/`` (see tests/test_pg_fixture_smoke.py).
"""

from __future__ import annotations

from unittest.mock import MagicMock, call

from app.db import database, galera


# ---------------------------------------------------------------------------
# database.execute_query -> db.executesql (real Postgres)
# ---------------------------------------------------------------------------


def test_execute_query_uses_executesql(pg_db, monkeypatch):
    """execute_query() routes through penguin-dal's executesql on real PG."""
    monkeypatch.setattr(database, "get_db", lambda: pg_db)
    assert database.execute_query("SELECT 1") == [(1,)]


def test_execute_query_named_placeholders(pg_db, monkeypatch):
    """execute_query() accepts driver-native %(name)s placeholders (not :name)."""
    monkeypatch.setattr(database, "get_db", lambda: pg_db)
    result = database.execute_query("SELECT %(value)s", {"value": 42})
    assert result == [(42,)]


def test_execute_query_fetch_false_returns_none(pg_db, monkeypatch):
    """execute_query(fetch=False) still executes the statement but returns None."""
    monkeypatch.setattr(database, "get_db", lambda: pg_db)
    result = database.execute_query("SELECT 1", fetch=False)
    assert result is None


# ---------------------------------------------------------------------------
# galera.set_wsrep_sync_wait -> db.executesql (SQL-assertion, MySQL-only syntax)
# ---------------------------------------------------------------------------


def test_set_wsrep_sync_wait_calls_executesql(monkeypatch):
    monkeypatch.setenv("DB_GALERA_ENABLED", "true")
    mock_db = MagicMock()

    assert galera.set_wsrep_sync_wait(mock_db, level=2) is True

    mock_db.executesql.assert_called_once_with(
        "SET SESSION wsrep_sync_wait = %(level)s", {"level": 2}
    )


def test_set_wsrep_sync_wait_disabled_skips_executesql(monkeypatch):
    monkeypatch.setenv("DB_GALERA_ENABLED", "false")
    mock_db = MagicMock()

    assert galera.set_wsrep_sync_wait(mock_db, level=2) is True
    mock_db.executesql.assert_not_called()


def test_set_wsrep_sync_wait_handles_executesql_error(monkeypatch):
    monkeypatch.setenv("DB_GALERA_ENABLED", "true")
    mock_db = MagicMock()
    mock_db.executesql.side_effect = Exception("boom")

    assert galera.set_wsrep_sync_wait(mock_db, level=1) is False


# ---------------------------------------------------------------------------
# galera.set_auto_increment_config -> db.transaction() + Tx.executesql
# ---------------------------------------------------------------------------


def test_set_auto_increment_config_calls_executesql_in_transaction(monkeypatch):
    monkeypatch.setenv("DB_GALERA_ENABLED", "true")
    monkeypatch.setenv("DB_GALERA_AUTO_INCREMENT_OFFSET", "3")
    monkeypatch.setenv("DB_GALERA_AUTO_INCREMENT_INCREMENT", "5")

    mock_tx = MagicMock()
    mock_db = MagicMock()
    mock_db.transaction.return_value.__enter__.return_value = mock_tx

    assert galera.set_auto_increment_config(mock_db) is True

    mock_tx.executesql.assert_has_calls(
        [
            call("SET SESSION auto_increment_offset = %(offset)s", {"offset": 3}),
            call(
                "SET SESSION auto_increment_increment = %(increment)s",
                {"increment": 5},
            ),
        ]
    )


def test_set_auto_increment_config_disabled_skips_transaction(monkeypatch):
    monkeypatch.setenv("DB_GALERA_ENABLED", "false")
    mock_db = MagicMock()

    assert galera.set_auto_increment_config(mock_db) is True
    mock_db.transaction.assert_not_called()


def test_set_auto_increment_config_handles_transaction_error(monkeypatch):
    monkeypatch.setenv("DB_GALERA_ENABLED", "true")
    mock_db = MagicMock()
    mock_db.transaction.side_effect = Exception("boom")

    assert galera.set_auto_increment_config(mock_db) is False


# ---------------------------------------------------------------------------
# galera.get_cluster_status -> db.executesql (SQL-assertion, MySQL-only syntax)
# ---------------------------------------------------------------------------


def test_get_cluster_status_calls_executesql(monkeypatch):
    monkeypatch.setenv("DB_GALERA_ENABLED", "true")
    mock_db = MagicMock()
    mock_db.executesql.return_value = [
        ("wsrep_cluster_size", "3"),
        ("wsrep_ready", "ON"),
    ]

    status = galera.get_cluster_status(mock_db)

    assert status == {"wsrep_cluster_size": "3", "wsrep_ready": "ON"}
    mock_db.executesql.assert_called_once_with(
        "SHOW STATUS WHERE Variable_name IN ("
        "'wsrep_cluster_size', "
        "'wsrep_cluster_status', "
        "'wsrep_ready', "
        "'wsrep_connected', "
        "'wsrep_local_state_comment'"
        ")"
    )


def test_get_cluster_status_disabled_returns_none(monkeypatch):
    monkeypatch.setenv("DB_GALERA_ENABLED", "false")
    mock_db = MagicMock()

    assert galera.get_cluster_status(mock_db) is None
    mock_db.executesql.assert_not_called()


def test_get_cluster_status_handles_executesql_error(monkeypatch):
    monkeypatch.setenv("DB_GALERA_ENABLED", "true")
    mock_db = MagicMock()
    mock_db.executesql.side_effect = Exception("boom")

    assert galera.get_cluster_status(mock_db) is None
