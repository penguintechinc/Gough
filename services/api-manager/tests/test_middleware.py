"""Tests for app/middleware.py authentication and authorization middleware."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import jwt as pyjwt
import pytest
from quart import Quart, g, jsonify


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app() -> Quart:
    app = Quart(__name__)
    app.config["JWT_SECRET_KEY"] = "test-secret-key-for-middleware-tests-32"
    app.config["TESTING"] = True
    return app


def _make_token(
    app: Quart,
    *,
    sub: str = "1",
    token_type: str = "access",
    scope: str = "gough.cluster.admin",
    extra: dict | None = None,
) -> str:
    payload: dict = {
        "sub": sub,
        "type": token_type,
        "scope": scope,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    if extra:
        payload.update(extra)
    return pyjwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")


def _make_expired_token(app: Quart) -> str:
    payload = {
        "sub": "1",
        "type": "access",
        "scope": "gough.cluster.admin",
        "iat": int(time.time()) - 7200,
        "exp": int(time.time()) - 3600,
    }
    return pyjwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")


_FAKE_USER = {
    "id": 1,
    "email": "test@example.com",
    "role": "admin",
    "is_active": True,
}

_FAKE_VIEWER = {
    "id": 2,
    "email": "viewer@example.com",
    "role": "viewer",
    "is_active": True,
}


# ---------------------------------------------------------------------------
# decode_token (pure function, uses app.config so needs app context)
# ---------------------------------------------------------------------------

class TestDecodeToken:
    @pytest.mark.anyio
    async def test_valid_token(self):
        app = _make_app()
        async with app.app_context():
            from app.middleware import decode_token
            token = _make_token(app)
            payload = decode_token(token)
            assert payload is not None
            assert payload["sub"] == "1"

    @pytest.mark.anyio
    async def test_expired_token_returns_none(self):
        app = _make_app()
        async with app.app_context():
            from app.middleware import decode_token
            token = _make_expired_token(app)
            assert decode_token(token) is None

    @pytest.mark.anyio
    async def test_invalid_token_returns_none(self):
        app = _make_app()
        async with app.app_context():
            from app.middleware import decode_token
            assert decode_token("not.a.token") is None

    @pytest.mark.anyio
    async def test_wrong_secret_returns_none(self):
        app = _make_app()
        token = pyjwt.encode(
            {"sub": "1", "exp": int(time.time()) + 3600},
            "wrong-secret",
            algorithm="HS256",
        )
        async with app.app_context():
            from app.middleware import decode_token
            assert decode_token(token) is None


# ---------------------------------------------------------------------------
# get_current_user
# ---------------------------------------------------------------------------

class TestGetCurrentUser:
    @pytest.mark.anyio
    async def test_returns_none_when_not_set(self):
        app = _make_app()
        async with app.test_request_context("/"):
            from app.middleware import get_current_user
            assert get_current_user() is None

    @pytest.mark.anyio
    async def test_returns_user_when_set(self):
        app = _make_app()
        async with app.test_request_context("/"):
            from app.middleware import get_current_user
            g.current_user = _FAKE_USER
            assert get_current_user() == _FAKE_USER


# ---------------------------------------------------------------------------
# user_has_role
# ---------------------------------------------------------------------------

class TestUserHasRole:
    @pytest.mark.anyio
    async def test_returns_false_when_no_user(self):
        app = _make_app()
        async with app.test_request_context("/"):
            from app.middleware import user_has_role
            assert user_has_role("admin") is False

    @pytest.mark.anyio
    async def test_returns_true_for_matching_role(self):
        app = _make_app()
        async with app.test_request_context("/"):
            from app.middleware import user_has_role
            g.current_user = _FAKE_USER
            assert user_has_role("admin") is True

    @pytest.mark.anyio
    async def test_returns_false_for_wrong_role(self):
        app = _make_app()
        async with app.test_request_context("/"):
            from app.middleware import user_has_role
            g.current_user = _FAKE_USER
            assert user_has_role("viewer") is False


# ---------------------------------------------------------------------------
# get_token_from_header
# ---------------------------------------------------------------------------

class TestGetTokenFromHeader:
    @pytest.mark.anyio
    async def test_bearer_token_extracted(self):
        app = _make_app()
        async with app.test_request_context(
            "/", headers={"Authorization": "Bearer mytoken"}
        ):
            from app.middleware import get_token_from_header
            assert get_token_from_header() == "mytoken"

    @pytest.mark.anyio
    async def test_missing_header_returns_none(self):
        app = _make_app()
        async with app.test_request_context("/"):
            from app.middleware import get_token_from_header
            assert get_token_from_header() is None

    @pytest.mark.anyio
    async def test_non_bearer_header_returns_none(self):
        app = _make_app()
        async with app.test_request_context(
            "/", headers={"Authorization": "Basic abc123"}
        ):
            from app.middleware import get_token_from_header
            assert get_token_from_header() is None


# ---------------------------------------------------------------------------
# auth_required
# ---------------------------------------------------------------------------

class TestAuthRequired:
    @pytest.mark.anyio
    async def test_missing_token_returns_401(self):
        app = _make_app()
        with patch("app.middleware.get_user_by_id", return_value=_FAKE_USER):
            from app.middleware import auth_required

            @auth_required
            async def protected():
                return jsonify({"ok": True}), 200

            async with app.test_request_context("/"):
                response, status = await protected()
                assert status == 401

    @pytest.mark.anyio
    async def test_valid_token_calls_handler(self):
        app = _make_app()
        token = _make_token(app)

        with patch("app.middleware.get_user_by_id", return_value=_FAKE_USER):
            from app.middleware import auth_required

            @auth_required
            async def protected():
                return jsonify({"ok": True}), 200

            async with app.test_request_context(
                "/", headers={"Authorization": f"Bearer {token}"}
            ):
                response, status = await protected()
                assert status == 200

    @pytest.mark.anyio
    async def test_expired_token_returns_401(self):
        app = _make_app()
        token = _make_expired_token(app)

        with patch("app.middleware.get_user_by_id", return_value=_FAKE_USER):
            from app.middleware import auth_required

            @auth_required
            async def protected():
                return jsonify({"ok": True}), 200

            async with app.test_request_context(
                "/", headers={"Authorization": f"Bearer {token}"}
            ):
                response, status = await protected()
                assert status == 401

    @pytest.mark.anyio
    async def test_wrong_token_type_returns_401(self):
        app = _make_app()
        token = _make_token(app, token_type="refresh")

        with patch("app.middleware.get_user_by_id", return_value=_FAKE_USER):
            from app.middleware import auth_required

            @auth_required
            async def protected():
                return jsonify({"ok": True}), 200

            async with app.test_request_context(
                "/", headers={"Authorization": f"Bearer {token}"}
            ):
                response, status = await protected()
                assert status == 401

    @pytest.mark.anyio
    async def test_user_not_found_returns_401(self):
        app = _make_app()
        token = _make_token(app)

        with patch("app.middleware.get_user_by_id", return_value=None):
            from app.middleware import auth_required

            @auth_required
            async def protected():
                return jsonify({"ok": True}), 200

            async with app.test_request_context(
                "/", headers={"Authorization": f"Bearer {token}"}
            ):
                response, status = await protected()
                assert status == 401

    @pytest.mark.anyio
    async def test_inactive_user_returns_401(self):
        app = _make_app()
        token = _make_token(app)
        inactive_user = {**_FAKE_USER, "is_active": False}

        with patch("app.middleware.get_user_by_id", return_value=inactive_user):
            from app.middleware import auth_required

            @auth_required
            async def protected():
                return jsonify({"ok": True}), 200

            async with app.test_request_context(
                "/", headers={"Authorization": f"Bearer {token}"}
            ):
                response, status = await protected()
                assert status == 401

    @pytest.mark.anyio
    async def test_sets_g_current_user(self):
        app = _make_app()
        token = _make_token(app)
        captured = {}

        with patch("app.middleware.get_user_by_id", return_value=_FAKE_USER):
            from app.middleware import auth_required

            @auth_required
            async def protected():
                captured["user"] = g.current_user
                return jsonify({}), 200

            async with app.test_request_context(
                "/", headers={"Authorization": f"Bearer {token}"}
            ):
                await protected()
                assert captured["user"]["id"] == 1
                assert "_jwt_payload" in captured["user"]

    @pytest.mark.anyio
    async def test_missing_sub_in_payload_returns_401(self):
        """Token without 'sub' claim."""
        app = _make_app()
        # Create token without sub
        payload = {
            "type": "access",
            "scope": "gough.cluster.admin",
            "exp": int(time.time()) + 3600,
        }
        token = pyjwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")

        with patch("app.middleware.get_user_by_id", return_value=_FAKE_USER):
            from app.middleware import auth_required

            @auth_required
            async def protected():
                return jsonify({"ok": True}), 200

            async with app.test_request_context(
                "/", headers={"Authorization": f"Bearer {token}"}
            ):
                response, status = await protected()
                assert status == 401


# ---------------------------------------------------------------------------
# admin_required
# ---------------------------------------------------------------------------

class TestAdminRequired:
    @pytest.mark.anyio
    async def test_admin_user_passes(self):
        app = _make_app()
        admin_user = {
            **_FAKE_USER,
            "role": "admin",
            "_jwt_payload": {"scope": "gough.cluster.admin"},
        }

        from app.middleware import admin_required

        @admin_required
        async def protected():
            return jsonify({"ok": True}), 200

        async with app.test_request_context("/"):
            g.current_user = admin_user
            response, status = await protected()
            assert status == 200

    @pytest.mark.anyio
    async def test_no_user_returns_401(self):
        app = _make_app()
        from app.middleware import admin_required

        @admin_required
        async def protected():
            return jsonify({"ok": True}), 200

        async with app.test_request_context("/"):
            response, status = await protected()
            assert status == 401

    @pytest.mark.anyio
    async def test_non_admin_role_returns_403(self):
        app = _make_app()
        viewer_user = {**_FAKE_VIEWER, "_jwt_payload": {"scope": ""}}

        from app.middleware import admin_required

        @admin_required
        async def protected():
            return jsonify({"ok": True}), 200

        async with app.test_request_context("/"):
            g.current_user = viewer_user
            response, status = await protected()
            assert status == 403


# ---------------------------------------------------------------------------
# roles_required
# ---------------------------------------------------------------------------

class TestRolesRequired:
    @pytest.mark.anyio
    async def test_matching_role_passes_via_scope(self):
        app = _make_app()
        admin_user = {
            **_FAKE_USER,
            "role": "admin",
            "_jwt_payload": {"scope": "gough.cluster.admin"},
        }

        from app.middleware import roles_required

        @roles_required("admin")
        async def protected():
            return jsonify({"ok": True}), 200

        async with app.test_request_context("/"):
            g.current_user = admin_user
            response, status = await protected()
            assert status == 200

    @pytest.mark.anyio
    async def test_non_matching_role_returns_403(self):
        app = _make_app()
        viewer_user = {**_FAKE_VIEWER, "_jwt_payload": {"scope": ""}}

        from app.middleware import roles_required

        @roles_required("admin")
        async def protected():
            return jsonify({"ok": True}), 200

        async with app.test_request_context("/"):
            g.current_user = viewer_user
            response, status = await protected()
            assert status == 403


# ---------------------------------------------------------------------------
# roles_accepted
# ---------------------------------------------------------------------------

class TestRolesAccepted:
    @pytest.mark.anyio
    async def test_one_of_multiple_roles_passes(self):
        app = _make_app()
        maintainer_user = {
            "id": 3,
            "email": "m@example.com",
            "role": "maintainer",
            "is_active": True,
            "_jwt_payload": {"scope": "gough.cluster.read"},
        }

        from app.middleware import roles_accepted

        @roles_accepted("admin", "maintainer")
        async def protected():
            return jsonify({"ok": True}), 200

        async with app.test_request_context("/"):
            g.current_user = maintainer_user
            response, status = await protected()
            assert status == 200


# ---------------------------------------------------------------------------
# maintainer_or_admin_required
# ---------------------------------------------------------------------------

class TestMaintainerOrAdminRequired:
    @pytest.mark.anyio
    async def test_maintainer_passes_via_legacy_role(self):
        app = _make_app()
        maintainer_user = {
            "id": 3,
            "email": "m@example.com",
            "role": "maintainer",
            "is_active": True,
            "_jwt_payload": {"scope": "gough.cluster.read"},
        }

        from app.middleware import maintainer_or_admin_required

        @maintainer_or_admin_required
        async def protected():
            return jsonify({"ok": True}), 200

        async with app.test_request_context("/"):
            g.current_user = maintainer_user
            response, status = await protected()
            assert status == 200


# ---------------------------------------------------------------------------
# safe_import helpers
# ---------------------------------------------------------------------------

class TestSafeImports:
    def test_safe_import_tenant_does_not_raise(self):
        from app.middleware import safe_import_tenant_middleware
        result = safe_import_tenant_middleware()
        # May return None or callable depending on environment
        assert result is None or callable(result)

    def test_safe_import_scope_does_not_raise(self):
        from app.middleware import safe_import_scope_enforcement
        result = safe_import_scope_enforcement()
        assert result is None or (isinstance(result, tuple) and len(result) == 3)


# ---------------------------------------------------------------------------
# _ROLE_TO_SCOPE_BUNDLE constant
# ---------------------------------------------------------------------------

class TestRoleToScopeBundle:
    def test_admin_bundle_exists(self):
        from app.middleware import _ROLE_TO_SCOPE_BUNDLE
        assert "admin" in _ROLE_TO_SCOPE_BUNDLE
        assert "gough.cluster.admin" in _ROLE_TO_SCOPE_BUNDLE["admin"]

    def test_maintainer_bundle_exists(self):
        from app.middleware import _ROLE_TO_SCOPE_BUNDLE
        assert "maintainer" in _ROLE_TO_SCOPE_BUNDLE

    def test_viewer_bundle_exists(self):
        from app.middleware import _ROLE_TO_SCOPE_BUNDLE
        assert "viewer" in _ROLE_TO_SCOPE_BUNDLE
