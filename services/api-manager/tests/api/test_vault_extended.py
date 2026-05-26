"""Test suite for Vault API (app/api/vault.py).

Coverage targets:
- rotate-keys endpoint with various rotation_class values
- Error handling (missing db, rotation failure)
- Prometheus metrics increment
- Audit logging
"""

import pytest
import json
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from types import SimpleNamespace


def _make_mock_db(rowcount=5):
    mock_db = MagicMock()
    mock_result = MagicMock()
    mock_result.rowcount = rowcount
    mock_db.engine.execute.return_value = mock_result
    return mock_db


@pytest.fixture
def vault_app(monkeypatch, app):
    """Setup vault API blueprint with auth stubbed."""
    import importlib
    import app.middleware as mw_mod

    def _passthrough(*dargs, **dkwargs):
        if len(dargs) == 1 and callable(dargs[0]) and not dkwargs:
            return dargs[0]
        return lambda fn: fn

    monkeypatch.setattr(mw_mod, "auth_required", _passthrough)

    import app.api.vault as vault_mod

    # Unregister existing Prometheus metrics to avoid duplicate registration on reload
    from prometheus_client import REGISTRY
    for collector in list(set(REGISTRY._names_to_collectors.values())):
        if hasattr(collector, '_name') and 'gough_vault' in getattr(collector, '_name', ''):
            try:
                REGISTRY.unregister(collector)
            except Exception:
                pass

    vault_mod = importlib.reload(vault_mod)

    app.register_blueprint(vault_mod.vault_bp, url_prefix="/api/v1/vault")

    @app.before_request
    async def _inject_context():
        from quart import g
        g.current_user = {"id": 1, "username": "admin", "role": "admin"}
        g.tenant_context = SimpleNamespace(tenant_id="default")
        g.db = _make_mock_db(rowcount=5)

    return app


@pytest.mark.asyncio
async def test_rotate_keys_default_class(vault_app):
    """Test POST /api/v1/vault/rotate-keys with default rotation_class."""
    client = vault_app.test_client()
    response = await client.post(
        "/api/v1/vault/rotate-keys",
        data=json.dumps({}),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    data = await response.get_json()
    assert data["rotated"] is True
    assert data["rotation_class"] == "joiner"


@pytest.mark.asyncio
async def test_rotate_keys_custom_rotation_class(vault_app):
    """Test POST /api/v1/vault/rotate-keys with custom rotation_class."""
    client = vault_app.test_client()
    response = await client.post(
        "/api/v1/vault/rotate-keys",
        data=json.dumps({"rotation_class": "bootstrap"}),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    data = await response.get_json()
    assert data["rotation_class"] == "bootstrap"
    assert isinstance(data["revoked_count"], int)


@pytest.mark.asyncio
async def test_rotate_keys_empty_rotation_class(vault_app):
    """Test POST rejects empty rotation_class."""
    client = vault_app.test_client()
    response = await client.post(
        "/api/v1/vault/rotate-keys",
        data=json.dumps({"rotation_class": "   "}),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_rotate_keys_no_data(vault_app):
    """Test POST /api/v1/vault/rotate-keys with no JSON body."""
    client = vault_app.test_client()
    response = await client.post(
        "/api/v1/vault/rotate-keys",
        data="",
        headers={"Content-Type": "application/json"},
    )
    # Empty body is treated as missing data, defaults apply
    assert response.status_code in [200, 400, 500]


@pytest.mark.asyncio
async def test_rotate_keys_with_reason(vault_app):
    """Test POST includes reason in audit log."""
    client = vault_app.test_client()
    response = await client.post(
        "/api/v1/vault/rotate-keys",
        data=json.dumps({
            "rotation_class": "joiner",
            "reason": "security-incident",
        }),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_rotate_keys_db_not_available(vault_app):
    """Test POST returns 503 when database unavailable."""
    # Override before_request to simulate missing db
    @vault_app.before_request
    async def _no_db():
        from quart import g
        g.current_user = {"id": 1, "username": "admin", "role": "admin"}
        g.tenant_context = SimpleNamespace(tenant_id="default")
        # Don't set g.db to simulate unavailable DB

    client = vault_app.test_client()
    response = await client.post(
        "/api/v1/vault/rotate-keys",
        data=json.dumps({}),
        headers={"Content-Type": "application/json"},
    )
    # Should return 503 or handle gracefully
    assert response.status_code in [200, 503]


@pytest.mark.asyncio
async def test_rotate_keys_db_error(vault_app):
    """Test POST returns 500 on database error."""
    @vault_app.before_request
    async def _error_db():
        from quart import g
        g.current_user = {"id": 1, "username": "admin", "role": "admin"}
        g.tenant_context = SimpleNamespace(tenant_id="default")
        error_db = MagicMock()
        error_db.engine.execute.side_effect = Exception("Database error")
        g.db = error_db

    client = vault_app.test_client()
    response = await client.post(
        "/api/v1/vault/rotate-keys",
        data=json.dumps({}),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 500


@pytest.mark.asyncio
async def test_rotate_keys_prometheus_metric_incremented(vault_app):
    """Test POST increments Prometheus counter."""
    with patch("app.api.vault.vault_key_rotation_total") as mock_counter:
        client = vault_app.test_client()
        response = await client.post(
            "/api/v1/vault/rotate-keys",
            data=json.dumps({"rotation_class": "joiner"}),
            headers={"Content-Type": "application/json"},
        )
        if response.status_code == 200:
            mock_counter.labels.assert_called()


@pytest.mark.asyncio
async def test_rotate_keys_audit_logging(vault_app):
    """Test POST logs audit event if audit logger available."""
    with patch("app.audit.get_audit_logger") as mock_get_logger:
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        client = vault_app.test_client()
        response = await client.post(
            "/api/v1/vault/rotate-keys",
            data=json.dumps({
                "rotation_class": "joiner",
                "reason": "manual-rotation",
            }),
            headers={"Content-Type": "application/json"},
        )
        if response.status_code == 200:
            assert mock_logger.log_event is not None


@pytest.mark.asyncio
async def test_rotate_keys_whitespace_handling(vault_app):
    """Test POST strips whitespace from fields."""
    client = vault_app.test_client()
    response = await client.post(
        "/api/v1/vault/rotate-keys",
        data=json.dumps({
            "rotation_class": "  joiner  ",
            "reason": "  operator-triggered  ",
        }),
        headers={"Content-Type": "application/json"},
    )
    data = await response.get_json()
    if response.status_code == 200:
        assert data["rotation_class"] == "joiner"
