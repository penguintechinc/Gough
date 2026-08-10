"""Regression tests for GH-31 and related auth blocker bugs.

Every test here drives the REAL authentication middleware chain via the
``real_auth_env`` fixture (see tests/api/conftest.py): the production
``wire_middleware`` stack (``_credential_validation`` -> tenant -> scope
enforcement) is installed, and ``g.current_user`` is populated ONLY by a valid
``Authorization: Bearer`` token flowing through ``_credential_validation``.
Nothing is pre-injected -- so an assertion only passes if the code under test
actually behaves, not because a fixture faked a principal.

Bugs covered:

Bug 1 -- Login/refresh/password-reset must be reachable without a token.
  Root cause: missing from ANONYMOUS_PATHS -> fail-closed scope layer returned
  403 for everyone. Proven by driving the real anonymous path (not a 404 on an
  unregistered route).

Bug 2 -- Valid tokens must reach policy-covered routes (middleware ordering).
  ``_credential_validation`` runs BEFORE ``_enforce_scopes``, so g.current_user
  is set before the scope check reads it. Proven by a real JWT -> seeded user ->
  200, with the negative cases (no token, garbage, missing scope) still failing
  closed.

Bug 3 -- me/logout/change-password need SCOPE_POLICY entries (frozenset()).
  Missing entries -> fail-closed 403 for valid tokens too. Proven by a valid
  token reaching the handler (not 403) AND a missing token being rejected (401).
"""

from __future__ import annotations

import pytest

# asyncio_mode=auto (root pytest.ini) auto-collects these; the marker is kept
# explicit for clarity.
pytestmark = pytest.mark.asyncio


# ==============================================================================
# BUG 1: Login / refresh / password-reset must be publicly reachable
# ==============================================================================


class TestAnonymousEndpointsReachableWithoutToken:
    """Anonymous auth endpoints must NOT fail-closed to 403 - regression: gh-31.

    These run through the real middleware chain. Because the endpoints are in
    ANONYMOUS_PATHS, ``_credential_validation`` and ``_enforce_scopes`` both skip
    them and the request reaches the handler (which returns 400/401/200 on its
    own merits) -- never the fail-closed 403 the middleware would emit for an
    unregistered protected path.
    """

    async def test_login_without_token_reaches_handler(self, real_auth_env):
        """POST /login without a token reaches the handler -> 401 bad creds, not 403."""
        resp = await real_auth_env.client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@gough.test", "password": "wrong"},
        )
        assert resp.status_code != 403, "login must be in ANONYMOUS_PATHS"
        assert resp.status_code == 401  # invalid credentials, handler reached

    async def test_login_missing_body_is_validation_error_not_403(self, real_auth_env):
        """Login validation errors surface as 400, never a fail-closed 403."""
        resp = await real_auth_env.client.post("/api/v1/auth/login", json={})
        assert resp.status_code != 403
        assert resp.status_code == 400

    async def test_refresh_without_access_token_reaches_handler(self, real_auth_env):
        """POST /refresh (refresh token in body, no Authorization) -> 401, not 403."""
        resp = await real_auth_env.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "dummy_token_12345"},
        )
        assert resp.status_code != 403, "refresh must be in ANONYMOUS_PATHS"
        assert resp.status_code == 401  # no matching refresh token, handler reached

    async def test_refresh_missing_body_is_validation_error_not_403(self, real_auth_env):
        """Refresh without a token body is a 400 validation error, not 403."""
        resp = await real_auth_env.client.post("/api/v1/auth/refresh", json={})
        assert resp.status_code != 403
        assert resp.status_code == 400

    async def test_request_password_reset_reaches_handler(self, real_auth_env):
        """POST /request-password-reset without a token -> 200 (never leaks), not 403."""
        resp = await real_auth_env.client.post(
            "/api/v1/auth/request-password-reset",
            json={"email": "nobody@gough.test"},
        )
        assert resp.status_code != 403, "request-password-reset must be anonymous"
        assert resp.status_code == 200  # handler reached (existence not leaked)

    async def test_reset_password_reaches_handler(self, real_auth_env):
        """POST /reset-password (reset_token in body) -> 401 bad token, not 403."""
        resp = await real_auth_env.client.post(
            "/api/v1/auth/reset-password",
            json={"reset_token": "dummy_token", "new_password": "newpassword123"},
        )
        assert resp.status_code != 403, "reset-password must be anonymous"
        assert resp.status_code == 401  # no matching reset token, handler reached


# ==============================================================================
# BUG 2: Valid tokens must reach policy-covered routes; bad ones must be rejected
# ==============================================================================


class TestPolicyCoveredRouteRealAuth:
    """GET /api/v1/nodes through the real chain - regression: gh-31 (Bug 2).

    GET /api/v1/nodes is in SCOPE_POLICY requiring ``gough.nodes.read``. These
    tests mint real HS256 tokens (same secret/alg decode_token verifies) against
    a seeded ACTIVE user, so g.current_user is populated solely by
    _credential_validation running before _enforce_scopes.
    """

    async def test_valid_token_reaches_route_not_401(self, real_auth_env):
        """Valid, correctly-scoped token -> 200 (reaches the route), never 401.

        This is the genuine "Bug 2 does not manifest" proof: a real token flows
        through _credential_validation, which sets g.current_user BEFORE
        _enforce_scopes reads it. Ordering bug -> this would be 401.
        """
        token = real_auth_env.mint(scope="gough.nodes.read")
        resp = await real_auth_env.client.get(
            "/api/v1/nodes", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code != 401, (
            "valid token was rejected -- g.current_user not populated before "
            "the scope check (middleware ordering regression)"
        )
        assert resp.status_code == 200

    async def test_no_authorization_header_returns_401(self, real_auth_env):
        """No Authorization header -> 401 from the scope layer (missing principal)."""
        resp = await real_auth_env.client.get("/api/v1/nodes")
        assert resp.status_code == 401

    async def test_garbage_token_returns_401(self, real_auth_env):
        """A non-JWT bearer value fails to decode -> no principal -> 401.

        This genuinely exercises _credential_validation's decode path: because
        g.current_user is NOT pre-injected, the garbage token must actually be
        decoded (and fail) for this to be 401.
        """
        resp = await real_auth_env.client.get(
            "/api/v1/nodes", headers={"Authorization": "Bearer not-a-jwt"}
        )
        assert resp.status_code == 401

    async def test_valid_token_missing_scope_returns_403(self, real_auth_env):
        """Authenticated but under-scoped token -> 403 (scope enforcement is live)."""
        token = real_auth_env.mint(scope="gough.cluster.read")  # lacks nodes.read
        resp = await real_auth_env.client.get(
            "/api/v1/nodes", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403

    async def test_valid_signature_unknown_user_returns_401(self, real_auth_env):
        """Well-signed token whose sub has no user row -> 401 (credential check)."""
        token = real_auth_env.mint(scope="gough.nodes.read", sub=999999)
        resp = await real_auth_env.client.get(
            "/api/v1/nodes", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401

    async def test_valid_scope_missing_tenant_claim_returns_403(self, real_auth_env):
        """Token without a tenant claim -> 403 from tenant middleware (runs first)."""
        token = real_auth_env.mint(scope="gough.nodes.read", tenant=None)
        resp = await real_auth_env.client.get(
            "/api/v1/nodes", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403

    async def test_expired_token_returns_401(self, real_auth_env):
        """An expired but otherwise-valid token fails to decode -> 401."""
        token = real_auth_env.mint(scope="gough.nodes.read", expired=True)
        resp = await real_auth_env.client.get(
            "/api/v1/nodes", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401


# ==============================================================================
# BUG 3: me / logout / change-password need SCOPE_POLICY entries (frozenset())
# ==============================================================================


class TestAuthenticatedEndpointsRealAuth:
    """me/logout/change-password require auth but no specific scope - gh-31 (Bug 3).

    Each is in SCOPE_POLICY with ``frozenset()`` (authenticated, any scope). The
    fix is proven two ways per endpoint:
      * valid token  -> NOT 403 (endpoint is registered; not fail-closed), and
      * missing token -> 401 (auth is still required; blocked at the scope layer
        before the handler ever runs).

    The valid-token requests carry a ``user_id`` claim so the auth blueprint's
    own ``require_auth`` decorator (which keys on ``user_id``) also passes,
    yielding a clean end-to-end response.
    """

    async def test_me_without_token_returns_401(self, real_auth_env):
        """GET /me with no token -> 401 (blocked at scope layer, handler unreached)."""
        resp = await real_auth_env.client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    async def test_me_with_valid_token_not_403(self, real_auth_env):
        """GET /me with a valid token -> reaches handler (200), never 403."""
        token = real_auth_env.mint(scope="", user_id=real_auth_env.user_id)
        resp = await real_auth_env.client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code != 403, "/me must be in SCOPE_POLICY with frozenset()"
        assert resp.status_code == 200

    async def test_logout_without_token_returns_401(self, real_auth_env):
        """POST /logout with no token -> 401 (auth required)."""
        resp = await real_auth_env.client.post(
            "/api/v1/auth/logout", json={"refresh_token": "x"}
        )
        assert resp.status_code == 401

    async def test_logout_with_valid_token_not_403(self, real_auth_env):
        """POST /logout with a valid token -> reaches handler (200), never 403."""
        token = real_auth_env.mint(scope="", user_id=real_auth_env.user_id)
        resp = await real_auth_env.client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
            json={},
        )
        assert resp.status_code != 403, "/logout must be in SCOPE_POLICY with frozenset()"
        assert resp.status_code == 200

    async def test_change_password_without_token_returns_401(self, real_auth_env):
        """POST /change-password with no token -> 401 (auth required)."""
        resp = await real_auth_env.client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "a", "new_password": "newpassword123"},
        )
        assert resp.status_code == 401

    async def test_change_password_with_valid_token_not_403(self, real_auth_env):
        """POST /change-password with a valid token -> reaches handler, never 403.

        A deliberately-incomplete body makes the handler return its own 400
        validation error, proving control passed the credential + scope layers
        (else 401/403) and reached the handler.
        """
        token = real_auth_env.mint(scope="", user_id=real_auth_env.user_id)
        resp = await real_auth_env.client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": "a"},  # new_password missing -> handler 400
        )
        assert resp.status_code != 403, (
            "/change-password must be in SCOPE_POLICY with frozenset()"
        )
        assert resp.status_code not in (401, 403)  # passed both middleware layers
        assert resp.status_code == 400  # handler's own validation error
