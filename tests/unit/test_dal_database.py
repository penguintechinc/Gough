"""Unit tests for penguin-dal database module (api-manager/app/db/database.py).

All tests use unittest.mock to avoid requiring a real database connection.
"""
import os
import sys

_API_MANAGER_PATH = '/home/penguin/code/gough/services/api-manager'
if _API_MANAGER_PATH not in sys.path:
    sys.path.insert(0, _API_MANAGER_PATH)
# Evict any stale 'app' module cached from another path (e.g. penguincode/app.py)
for _mod in list(sys.modules.keys()):
    if _mod == 'app' or _mod.startswith('app.'):
        del sys.modules[_mod]

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime


class TestInitDb:
    """Tests for init_db() function."""

    def test_init_db_returns_db_instance(self):
        """init_db() with explicit URL returns a DB instance."""
        with patch('app.db.database.DB') as mock_db_cls:
            mock_db_cls.return_value = MagicMock()
            from app.db.database import init_db
            result = init_db(database_url='sqlite:///:memory:', pool_size=5)
            mock_db_cls.assert_called_once_with('sqlite:///:memory:', pool_size=5)
            assert result is mock_db_cls.return_value

    def test_init_db_raises_without_url(self):
        """init_db() raises ValueError when no URL is provided and DATABASE_URL is not set."""
        import importlib
        import app.db.database as db_mod

        env = {k: v for k, v in os.environ.items() if k != 'DATABASE_URL'}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="DATABASE_URL"):
                db_mod.init_db()

    def test_init_db_uses_env_var(self):
        """init_db() reads DATABASE_URL from environment when no explicit URL given."""
        with patch('app.db.database.DB') as mock_db_cls:
            mock_db_cls.return_value = MagicMock()
            with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://localhost/test'}):
                from app.db.database import init_db
                result = init_db()
                mock_db_cls.assert_called_once()
                call_args = mock_db_cls.call_args
                assert call_args[0][0] == 'postgresql://localhost/test'

    def test_init_db_uses_default_pool_size(self):
        """init_db() uses pool_size=10 by default."""
        with patch('app.db.database.DB') as mock_db_cls:
            mock_db_cls.return_value = MagicMock()
            with patch.dict(os.environ, {'DATABASE_URL': 'sqlite:///:memory:'}):
                from app.db.database import init_db
                init_db()
                call_kwargs = mock_db_cls.call_args[1]
                assert call_kwargs.get('pool_size') == 10

    def test_init_db_explicit_pool_size(self):
        """init_db() passes explicit pool_size to DB constructor."""
        with patch('app.db.database.DB') as mock_db_cls:
            mock_db_cls.return_value = MagicMock()
            from app.db.database import init_db
            init_db(database_url='sqlite:///:memory:', pool_size=20)
            call_kwargs = mock_db_cls.call_args[1]
            assert call_kwargs.get('pool_size') == 20


class TestGetDb:
    """Tests for get_db() function."""

    def test_get_db_initialises_on_first_call(self):
        """get_db() calls init_db when thread-local DB is not set."""
        import app.db.database as db_mod
        # Clear any cached thread-local state
        if hasattr(db_mod._thread_local, 'db'):
            db_mod._thread_local.db = None

        mock_db = MagicMock()
        with patch('app.db.database.init_db', return_value=mock_db) as mock_init:
            result = db_mod.get_db()
            mock_init.assert_called_once()
            assert result is mock_db

    def test_get_db_returns_cached_instance(self):
        """get_db() returns the same DB instance when already initialised."""
        import app.db.database as db_mod
        existing_db = MagicMock()
        db_mod._thread_local.db = existing_db

        with patch('app.db.database.init_db') as mock_init:
            result = db_mod.get_db()
            mock_init.assert_not_called()
            assert result is existing_db

        # Clean up
        db_mod._thread_local.db = None


class TestCloseDb:
    """Tests for close_db() function."""

    def test_close_db_calls_close_and_sets_none(self):
        """close_db() calls db.close() and sets thread-local to None."""
        import app.db.database as db_mod
        mock_db = MagicMock()
        db_mod._thread_local.db = mock_db

        db_mod.close_db()

        mock_db.close.assert_called_once()
        assert db_mod._thread_local.db is None

    def test_close_db_safe_when_no_connection(self):
        """close_db() does not raise when no connection exists."""
        import app.db.database as db_mod
        db_mod._thread_local.db = None
        # Should not raise
        db_mod.close_db()

    def test_close_db_handles_close_exception(self):
        """close_db() sets thread-local to None even when close() raises."""
        import app.db.database as db_mod
        mock_db = MagicMock()
        mock_db.close.side_effect = RuntimeError("connection already closed")
        db_mod._thread_local.db = mock_db

        # Should not propagate exception
        db_mod.close_db()
        assert db_mod._thread_local.db is None


class TestGetDbContext:
    """Tests for get_db_context() context manager."""

    def test_context_yields_db_and_commits(self):
        """get_db_context() yields the DB and commits on exit."""
        mock_db = MagicMock()
        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import get_db_context
            with get_db_context() as db:
                assert db is mock_db
            mock_db.commit.assert_called_once()


class TestInsertApiDefinition:
    """Tests for insert_api_definition()."""

    def test_inserts_and_returns_id(self):
        """insert_api_definition() inserts a record and returns its ID."""
        mock_db = MagicMock()
        mock_db.api_definitions.insert.return_value = 42

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import insert_api_definition
            result = insert_api_definition('test', 'v1', '/test', 'GET')
            assert result == 42
            mock_db.api_definitions.insert.assert_called_once()

    def test_passes_required_fields(self):
        """insert_api_definition() passes name, version, path, method."""
        mock_db = MagicMock()
        mock_db.api_definitions.insert.return_value = 1

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import insert_api_definition
            insert_api_definition('myapi', 'v2', '/items', 'POST')
            call_kwargs = mock_db.api_definitions.insert.call_args[1]
            assert call_kwargs['name'] == 'myapi'
            assert call_kwargs['version'] == 'v2'
            assert call_kwargs['path'] == '/items'
            assert call_kwargs['method'] == 'POST'

    def test_passes_optional_fields(self):
        """insert_api_definition() passes description, openapi_spec, and enabled."""
        mock_db = MagicMock()
        mock_db.api_definitions.insert.return_value = 5

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import insert_api_definition
            insert_api_definition(
                name='test', version='v1', path='/test', method='PUT',
                description='A test API', openapi_spec={'openapi': '3.0'}, enabled=False
            )
            call_kwargs = mock_db.api_definitions.insert.call_args[1]
            assert call_kwargs['description'] == 'A test API'
            assert call_kwargs['openapi_spec'] == {'openapi': '3.0'}
            assert call_kwargs['enabled'] is False

    def test_default_enabled_is_true(self):
        """insert_api_definition() defaults enabled to True."""
        mock_db = MagicMock()
        mock_db.api_definitions.insert.return_value = 1

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import insert_api_definition
            insert_api_definition('test', 'v1', '/test', 'GET')
            call_kwargs = mock_db.api_definitions.insert.call_args[1]
            assert call_kwargs['enabled'] is True

    def test_commits_after_insert(self):
        """insert_api_definition() commits the transaction."""
        mock_db = MagicMock()
        mock_db.api_definitions.insert.return_value = 1

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import insert_api_definition
            insert_api_definition('test', 'v1', '/test', 'GET')
            mock_db.commit.assert_called_once()


class TestGetApiDefinitions:
    """Tests for get_api_definitions()."""

    def _make_mock_row(self, data: dict) -> MagicMock:
        row = MagicMock()
        row.as_dict.return_value = data
        return row

    def _make_mock_db_for_query(self, rows):
        """Build a MagicMock DB that supports the query pattern used in get_api_definitions.

        The source code does:
            query = db.api_definitions.id > 0
            rows = db(query).select()
        so the mock must support comparison operators on db.api_definitions.id.
        """
        mock_db = MagicMock()
        # Make comparison operators return a MagicMock (the query object)
        mock_db.api_definitions.id.__gt__ = MagicMock(return_value=MagicMock())
        mock_db.api_definitions.name.__eq__ = MagicMock(return_value=MagicMock())
        mock_db.api_definitions.version.__eq__ = MagicMock(return_value=MagicMock())
        mock_db.api_definitions.enabled.__eq__ = MagicMock(return_value=MagicMock())
        mock_db.return_value.select.return_value = rows
        return mock_db

    def test_returns_all_when_no_filters(self):
        """get_api_definitions() returns all records when no filters given."""
        rows = [
            self._make_mock_row({'id': 1, 'name': 'api1'}),
            self._make_mock_row({'id': 2, 'name': 'api2'}),
        ]
        mock_db = self._make_mock_db_for_query(rows)

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import get_api_definitions
            result = get_api_definitions()
            assert len(result) == 2
            assert result[0]['name'] == 'api1'

    def test_returns_empty_list_when_none_found(self):
        """get_api_definitions() returns an empty list when no records match."""
        mock_db = self._make_mock_db_for_query([])

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import get_api_definitions
            result = get_api_definitions(name='nonexistent')
            assert result == []

    def test_returns_list_of_dicts(self):
        """get_api_definitions() converts rows to dicts via as_dict()."""
        row = self._make_mock_row({'id': 3, 'name': 'myapi', 'enabled': True})
        mock_db = self._make_mock_db_for_query([row])

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import get_api_definitions
            result = get_api_definitions()
            assert isinstance(result, list)
            assert result[0]['name'] == 'myapi'
            row.as_dict.assert_called_once()

    def test_filters_by_version(self):
        """get_api_definitions() filters by version when provided."""
        row = self._make_mock_row({'id': 1, 'name': 'api', 'version': 'v2'})
        mock_db = self._make_mock_db_for_query([row])

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import get_api_definitions
            result = get_api_definitions(version='v2')
            assert len(result) == 1
            assert result[0]['version'] == 'v2'

    def test_filters_by_enabled(self):
        """get_api_definitions() filters by enabled status when provided."""
        row = self._make_mock_row({'id': 1, 'name': 'api', 'enabled': False})
        mock_db = self._make_mock_db_for_query([row])

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import get_api_definitions
            result = get_api_definitions(enabled=False)
            assert len(result) == 1
            assert result[0]['enabled'] is False


class TestGetApiKeyByHash:
    """Tests for get_api_key_by_hash()."""

    def test_returns_dict_when_found(self):
        """Returns dict representation when key exists."""
        mock_db = MagicMock()
        mock_row = MagicMock()
        mock_row.as_dict.return_value = {'key_hash': 'abc123', 'name': 'mykey'}
        mock_db.return_value.select.return_value.first.return_value = mock_row

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import get_api_key_by_hash
            result = get_api_key_by_hash('abc123')
            assert result == {'key_hash': 'abc123', 'name': 'mykey'}

    def test_returns_none_when_not_found(self):
        """Returns None when key hash is not in the database."""
        mock_db = MagicMock()
        mock_db.return_value.select.return_value.first.return_value = None

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import get_api_key_by_hash
            result = get_api_key_by_hash('nonexistent')
            assert result is None


class TestUpdateApiKeyLastUsed:
    """Tests for update_api_key_last_used()."""

    def test_returns_true_when_updated(self):
        """Returns True when a record is updated (affected rows > 0)."""
        mock_db = MagicMock()
        mock_db.return_value.update.return_value = 1

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import update_api_key_last_used
            result = update_api_key_last_used(1)
            assert result is True

    def test_returns_false_when_not_found(self):
        """Returns False when no record is updated (key ID not found)."""
        mock_db = MagicMock()
        mock_db.return_value.update.return_value = 0

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import update_api_key_last_used
            result = update_api_key_last_used(999)
            assert result is False

    def test_commits_after_update(self):
        """update_api_key_last_used() commits the transaction."""
        mock_db = MagicMock()
        mock_db.return_value.update.return_value = 1

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import update_api_key_last_used
            update_api_key_last_used(1)
            mock_db.commit.assert_called_once()


class TestInsertApiKey:
    """Tests for insert_api_key()."""

    def test_inserts_and_returns_id(self):
        """insert_api_key() inserts a record and returns its ID."""
        mock_db = MagicMock()
        mock_db.api_keys.insert.return_value = 7

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import insert_api_key
            result = insert_api_key(
                key_hash='hashed', name='mykey', user_id='user-1',
                scopes=['read', 'write']
            )
            assert result == 7

    def test_passes_all_fields(self):
        """insert_api_key() passes all fields to the DB."""
        mock_db = MagicMock()
        mock_db.api_keys.insert.return_value = 1
        expiry = datetime(2027, 1, 1)

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import insert_api_key
            insert_api_key(
                key_hash='h', name='k', user_id='u',
                scopes=['admin'], enabled=False, rate_limit=500, expires_at=expiry
            )
            call_kwargs = mock_db.api_keys.insert.call_args[1]
            assert call_kwargs['key_hash'] == 'h'
            assert call_kwargs['enabled'] is False
            assert call_kwargs['rate_limit'] == 500
            assert call_kwargs['expires_at'] == expiry

    def test_default_enabled_true(self):
        """insert_api_key() defaults enabled to True."""
        mock_db = MagicMock()
        mock_db.api_keys.insert.return_value = 1

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import insert_api_key
            insert_api_key(key_hash='h', name='k', user_id='u', scopes=[])
            call_kwargs = mock_db.api_keys.insert.call_args[1]
            assert call_kwargs['enabled'] is True

    def test_default_rate_limit(self):
        """insert_api_key() defaults rate_limit to 1000."""
        mock_db = MagicMock()
        mock_db.api_keys.insert.return_value = 1

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import insert_api_key
            insert_api_key(key_hash='h', name='k', user_id='u', scopes=[])
            call_kwargs = mock_db.api_keys.insert.call_args[1]
            assert call_kwargs['rate_limit'] == 1000


class TestInsertApiUsage:
    """Tests for insert_api_usage()."""

    def test_inserts_and_returns_id(self):
        """insert_api_usage() inserts usage record and returns its ID."""
        mock_db = MagicMock()
        mock_db.api_usage.insert.return_value = 100

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import insert_api_usage
            result = insert_api_usage(
                api_id=1, method='GET', path='/items',
                status_code=200, response_time_ms=45
            )
            assert result == 100

    def test_passes_optional_fields(self):
        """insert_api_usage() passes optional user_id, ip_address, user_agent."""
        mock_db = MagicMock()
        mock_db.api_usage.insert.return_value = 1

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import insert_api_usage
            insert_api_usage(
                api_id=2, method='POST', path='/items',
                status_code=201, response_time_ms=120,
                user_id='user-abc', ip_address='10.0.0.1', user_agent='pytest/1.0'
            )
            call_kwargs = mock_db.api_usage.insert.call_args[1]
            assert call_kwargs['user_id'] == 'user-abc'
            assert call_kwargs['ip_address'] == '10.0.0.1'
            assert call_kwargs['user_agent'] == 'pytest/1.0'


class TestExecuteQuery:
    """Tests for execute_query()."""

    def test_executes_query_with_fetch(self):
        """execute_query() executes a query and returns results when fetch=True."""
        mock_db = MagicMock()
        mock_conn = MagicMock()
        mock_result_row = MagicMock()
        mock_result_row._mapping = {'id': 1, 'name': 'test'}
        mock_conn.execute.return_value = [mock_result_row]
        mock_db.engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_db.engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import execute_query
            result = execute_query('SELECT * FROM users', fetch=True)
            assert isinstance(result, list)
            assert result[0]['id'] == 1
            assert result[0]['name'] == 'test'

    def test_executes_query_without_fetch(self):
        """execute_query() returns None when fetch=False."""
        mock_db = MagicMock()
        mock_conn = MagicMock()
        mock_db.engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_db.engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import execute_query
            result = execute_query('UPDATE users SET active = 1', fetch=False)
            assert result is None
            mock_conn.commit.assert_called_once()

    def test_binds_parameters(self):
        """execute_query() passes parameters to the query."""
        mock_db = MagicMock()
        mock_conn = MagicMock()
        mock_conn.execute.return_value = []
        mock_db.engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_db.engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import execute_query
            execute_query('SELECT * FROM users WHERE id = :id', params={'id': 123})
            call_args = mock_conn.execute.call_args
            assert call_args[0][1] == {'id': 123}

    def test_raises_on_exception(self):
        """execute_query() re-raises database exceptions."""
        mock_db = MagicMock()
        mock_db.engine.connect.side_effect = RuntimeError("connection failed")

        with patch('app.db.database.get_db', return_value=mock_db):
            from app.db.database import execute_query
            with pytest.raises(RuntimeError, match="connection failed"):
                execute_query('SELECT * FROM users')


class TestGetConnectionInfo:
    """Tests for get_connection_info()."""

    def test_returns_dict_with_db_type_and_tables(self):
        """get_connection_info() returns dict with db_type and tables keys."""
        mock_db = MagicMock()
        mock_db.tables = {'api_definitions': MagicMock(), 'api_keys': MagicMock()}

        with patch('app.db.database.get_db', return_value=mock_db):
            with patch.dict(os.environ, {'DB_TYPE': 'postgresql'}):
                from app.db.database import get_connection_info
                result = get_connection_info()
                assert result['db_type'] == 'postgresql'
                assert 'api_definitions' in result['tables']
                assert 'api_keys' in result['tables']

    def test_default_db_type_is_postgres(self):
        """get_connection_info() defaults DB_TYPE to 'postgres'."""
        mock_db = MagicMock()
        mock_db.tables = {}

        env = {k: v for k, v in os.environ.items() if k != 'DB_TYPE'}
        with patch('app.db.database.get_db', return_value=mock_db):
            with patch.dict(os.environ, env, clear=True):
                from app.db.database import get_connection_info
                result = get_connection_info()
                assert result['db_type'] == 'postgres'
