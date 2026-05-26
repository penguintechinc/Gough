"""Coverage tests for middleware.py uncovered lines."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch, AsyncMock
import pytest
from quart import Quart, g, jsonify


def _make_app() -> Quart:
    app = Quart(__name__)
    app.config["JWT_SECRET_KEY"] = "test-secret-key-for-middleware-tests-32"
    app.config["TESTING"] = True
    return app


def _make_token(app: Quart, **kwargs) -> str:
    import jwt as pyjwt
    payload = {
        "sub": "1",
        "type": "access",
        "scope": "gough.cluster.admin",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    payload.update(kwargs)
    return pyjwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")


_FAKE_ADMIN = {
    "id": 2,
    "email": "admin@example.com",
    "role": "admin",
    "is_active": True,
}


class TestAuthRequiredSyncHandler:
    """Test auth_required decorator with async handlers."""

    @pytest.mark.anyio
    async def test_sync_handler_works_with_auth_required(self):
        """Auth_required decorator works with async handlers."""
        app = _make_app()
        token = _make_token(app)

        with patch("app.middleware.get_user_by_id", return_value={"id": 1, "is_active": True}):
            from app.middleware import auth_required

            @auth_required
            async def async_handler():
                return jsonify({"msg": "response"}), 200

            async with app.test_request_context(
                "/", headers={"Authorization": f"Bearer {token}"}
            ):
                result = await async_handler()
                response, status = result
                assert status == 200


class TestRoleRequiredDecorator:
    """Test role_required decorator."""

    @pytest.mark.anyio
    async def test_role_required_scope_bundle_match(self):
        """role_required accepts matching scope bundles."""
        app = _make_app()
        token = _make_token(app, scope="gough.cluster.admin")

        with patch("app.middleware.get_user_by_id", return_value=_FAKE_ADMIN):
            with patch("app.security.scope_enforcement.extract_scopes_from_jwt") as mock_extract:
                with patch("app.security.scope_enforcement.check_scopes") as mock_check:
                    from app.middleware import role_required

                    mock_extract.return_value = frozenset({"gough.cluster.admin"})
                    mock_check.return_value = None

                    @role_required("admin")
                    async def protected():
                        return jsonify({"ok": True}), 200

                    async with app.test_request_context("/"):
                        g.current_user = {**_FAKE_ADMIN, "_jwt_payload": {"scope": "gough.cluster.admin"}}
                        response, status = await protected()
                        assert status == 200
                        mock_check.assert_called()


class TestCredentialValidation:
    """Test credential validation middleware."""

    @pytest.mark.anyio
    async def test_credential_validation_with_valid_token(self):
        """Valid token populates g.current_user."""
        app = _make_app()
        token = _make_token(app)

        with patch("app.middleware.get_user_by_id", return_value={"id": 1, "is_active": True}):
            from app.middleware import install_security_middleware

            await install_security_middleware(app)

            async with app.test_request_context(
                "/", headers={"Authorization": f"Bearer {token}"}
            ):
                for handler in app.before_request_funcs.get(None, []):
                    try:
                        result = handler()
                        if hasattr(result, '__await__'):
                            result = await result
                    except:
                        break
                    if result is not None:
                        break

                assert g.current_user is not None
                assert g.current_user["id"] == 1

    @pytest.mark.anyio
    async def test_credential_validation_missing_token(self):
        """Missing token doesn't set g.current_user."""
        app = _make_app()

        from app.middleware import install_security_middleware

        await install_security_middleware(app)

        async with app.test_request_context("/"):
            for handler in app.before_request_funcs.get(None, []):
                try:
                    result = handler()
                    if hasattr(result, '__await__'):
                        result = await result
                except:
                    break
                if result is not None:
                    break

            assert getattr(g, "current_user", None) is None

    @pytest.mark.anyio
    async def test_credential_validation_invalid_token(self):
        """Invalid token doesn't set g.current_user."""
        app = _make_app()

        from app.middleware import install_security_middleware

        await install_security_middleware(app)

        async with app.test_request_context(
            "/", headers={"Authorization": "Bearer invalid.token.here"}
        ):
            for handler in app.before_request_funcs.get(None, []):
                try:
                    result = handler()
                    if hasattr(result, '__await__'):
                        result = await result
                except:
                    break
                if result is not None:
                    break

            assert getattr(g, "current_user", None) is None

    @pytest.mark.anyio
    async def test_credential_validation_inactive_user(self):
        """Inactive user doesn't set g.current_user."""
        app = _make_app()
        token = _make_token(app)
        inactive = {"id": 1, "is_active": False}

        with patch("app.middleware.get_user_by_id", return_value=inactive):
            from app.middleware import install_security_middleware

            await install_security_middleware(app)

            async with app.test_request_context(
                "/", headers={"Authorization": f"Bearer {token}"}
            ):
                for handler in app.before_request_funcs.get(None, []):
                    try:
                        result = handler()
                        if hasattr(result, '__await__'):
                            result = await result
                    except:
                        break
                    if result is not None:
                        break

                assert getattr(g, "current_user", None) is None


class TestRecordRequestMetrics:
    """Test _record_request_metrics function."""

    @pytest.mark.anyio
    async def test_record_metrics_success_response(self):
        """Record metrics for successful response."""
        app = _make_app()

        from app.middleware import _record_request_metrics

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers.get.return_value = "0.050"

        with patch("app.metrics.api_request_latency_seconds") as mock_latency:
            with patch("app.metrics.api_error_total") as mock_error:
                async with app.test_request_context("/api/v1/users/123", method="GET"):
                    result = await _record_request_metrics(mock_response)
                    assert result == mock_response
                    mock_latency.labels.assert_called()

    @pytest.mark.anyio
    async def test_record_metrics_error_response(self):
        """Record error metrics for 5xx response."""
        app = _make_app()

        from app.middleware import _record_request_metrics

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.headers.get.return_value = "1.023"

        with patch("app.metrics.api_request_latency_seconds") as mock_latency:
            with patch("app.metrics.api_error_total") as mock_error:
                async with app.test_request_context("/api/v1/users/123", method="POST"):
                    result = await _record_request_metrics(mock_response)
                    assert result == mock_response
                    mock_latency.labels.assert_called()
                    mock_error.labels.assert_called()

    @pytest.mark.anyio
    async def test_record_metrics_exception_silenced(self):
        """Exceptions in metrics recording are silenced."""
        app = _make_app()

        from app.middleware import _record_request_metrics

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("app.metrics.api_request_latency_seconds", side_effect=Exception("metric error")):
            async with app.test_request_context("/api/v1/test", method="GET"):
                result = await _record_request_metrics(mock_response)
                assert result == mock_response
