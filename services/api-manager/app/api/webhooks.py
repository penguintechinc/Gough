"""Webhook configuration + JWKS API endpoints.

Spec reference (API Surface → Webhooks):

    GET    /api/v1/webhooks                 list endpoints (admin)
    POST   /api/v1/webhooks                 register endpoint (admin)
    DELETE /api/v1/webhooks/{id}            remove endpoint (admin)
    POST   /api/v1/webhooks/{id}/test       send synthetic test event (admin)
    GET    /api/v1/webhooks/keys/{tenant}   anonymous JWKS for verification

All admin endpoints require the ``gough.cluster.admin`` scope and a valid
tenant claim. The JWKS endpoint is anonymous so consumers can verify
asymmetric webhook signatures without authentication, which is also why it
intentionally never returns HMAC secrets.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

from quart import Blueprint, current_app, g, jsonify, request
from sqlalchemy import text

from ..middleware import auth_required
from ..security.scope_enforcement import require_scopes
from ..security.tenant import (
    TenantClaimMissingError,
    extract_tenant_from_jwt,
)
from ..security.webhook_keys import (
    ECDSA_P256_SHA256,
    ED25519,
    HMAC_SHA256,
    VALID_MODES,
    WebhookKeyManager,
)
from ..workers.webhook_dispatcher import WebhookDispatcher, WebhookEndpoint

log = logging.getLogger(__name__)

webhooks_bp = Blueprint("webhooks", __name__)

DEFAULT_SIGNING_MODE: str = ED25519
MAX_EVENT_FILTER_PATTERNS: int = 64
MAX_URL_LENGTH: int = 2048

_FILTER_PATTERN_RE = re.compile(r"^[a-zA-Z0-9_.\-*]{1,128}$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _vault_client() -> Any:
    """Return the application-wide Vault client.

    Tests inject ``current_app.vault_client`` directly; production paths fall
    back to ``hvac.Client(VAULT_ADDR)`` configured by the secrets layer.
    """
    client = getattr(current_app, "vault_client", None)
    if client is not None:
        return client
    raise RuntimeError("vault_client is not configured on the application")


def _key_manager() -> WebhookKeyManager:
    return WebhookKeyManager(_vault_client())


def _db_session() -> Any:
    """Return the SQLAlchemy session/engine connection for webhook storage."""
    factory = getattr(current_app, "webhook_db_factory", None)
    if factory is not None:
        return factory()
    db = getattr(current_app, "db", None)
    if db is None:
        raise RuntimeError("application has no db handle")
    # SQLAlchemy engine path.
    return db.engine.connect()


def _current_tenant() -> str:
    user = g.get("current_user") or {}
    payload = user.get("_jwt_payload", {}) if isinstance(user, dict) else {}
    ctx = extract_tenant_from_jwt(payload)
    return ctx.tenant_id


def _validate_url(url: str) -> tuple[bool, str]:
    if not isinstance(url, str) or not url:
        return False, "url is required"
    if len(url) > MAX_URL_LENGTH:
        return False, "url exceeds maximum length"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "url scheme must be http or https"
    if not parsed.netloc:
        return False, "url must include a host"
    return True, ""


def _validate_event_filter(value: Any) -> tuple[bool, str, list[str]]:
    if value is None:
        return True, "", []
    if not isinstance(value, list):
        return False, "event_filter must be a list", []
    if len(value) > MAX_EVENT_FILTER_PATTERNS:
        return False, "event_filter has too many patterns", []
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _FILTER_PATTERN_RE.match(item):
            return False, f"invalid event_filter pattern: {item!r}", []
        out.append(item)
    return True, "", out


def _validate_retry_policy(value: Any) -> tuple[bool, str, dict]:
    """Spec retries are server-mandated; ``retry_policy`` only carries the
    ``mode`` ("standard"|"none") plus optional ``max_attempts`` cap."""
    if value is None:
        return True, "", {"mode": "standard"}
    if not isinstance(value, dict):
        return False, "retry_policy must be an object", {}
    mode = value.get("mode", "standard")
    if mode not in ("standard", "none"):
        return False, "retry_policy.mode must be 'standard' or 'none'", {}
    max_attempts = value.get("max_attempts", 8)
    if not isinstance(max_attempts, int) or not (1 <= max_attempts <= 8):
        return False, "retry_policy.max_attempts must be 1..8", {}
    return True, "", {"mode": mode, "max_attempts": max_attempts}


def _row_to_dict(row: Any) -> dict:
    ef = row[5]
    if isinstance(ef, str):
        try:
            ef = json.loads(ef)
        except Exception:
            ef = []
    rp = row[6]
    if isinstance(rp, str):
        try:
            rp = json.loads(rp)
        except Exception:
            rp = {}
    return {
        "id": str(row[0]),
        "tenant_id": str(row[1]),
        "url": str(row[2]),
        "signing_mode": str(row[3]),
        "active": bool(row[4]),
        "event_filter": list(ef or []),
        "retry_policy": dict(rp or {}),
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@webhooks_bp.route("", methods=["GET"])
@auth_required
@require_scopes("gough.cluster.admin")
async def list_webhooks():
    """List webhook endpoints for the caller's tenant."""
    tenant_id = _current_tenant()
    conn = _db_session()
    try:
        rows = conn.execute(
            text(
                "SELECT id, tenant_id, url, signing_mode, active, event_filter, "
                "retry_policy FROM webhook_endpoints WHERE tenant_id = :t "
                "ORDER BY id"
            ),
            {"t": tenant_id},
        ).fetchall()
    finally:
        _close(conn)
    return jsonify({"endpoints": [_row_to_dict(r) for r in rows]}), 200


@webhooks_bp.route("", methods=["POST"])
@auth_required
@require_scopes("gough.cluster.admin")
async def create_webhook():
    """Register a webhook endpoint and provision its signing key."""
    tenant_id = _current_tenant()
    body = await request.get_json(silent=True) or {}

    url = body.get("url")
    ok, err = _validate_url(url)
    if not ok:
        return jsonify({"error": err}), 400

    signing_mode = body.get("signing_mode", DEFAULT_SIGNING_MODE)
    if signing_mode not in VALID_MODES:
        return (
            jsonify(
                {
                    "error": (
                        f"signing_mode must be one of "
                        f"{sorted(VALID_MODES)}"
                    )
                }
            ),
            400,
        )

    ok, err, event_filter = _validate_event_filter(body.get("event_filter"))
    if not ok:
        return jsonify({"error": err}), 400

    ok, err, retry_policy = _validate_retry_policy(body.get("retry_policy"))
    if not ok:
        return jsonify({"error": err}), 400

    # Provision Vault key (idempotent).
    try:
        _key_manager().ensure_keys_for_tenant(tenant_id, signing_mode)
    except Exception as exc:
        log.exception("failed to provision webhook signing key")
        return jsonify({"error": f"key_provisioning_failed: {exc}"}), 500

    conn = _db_session()
    try:
        result = conn.execute(
            text(
                "INSERT INTO webhook_endpoints "
                "(tenant_id, url, signing_mode, active, event_filter, retry_policy) "
                "VALUES (:t, :u, :m, TRUE, :ef, :rp) "
                "RETURNING id, tenant_id, url, signing_mode, active, "
                "event_filter, retry_policy"
            ),
            {
                "t": tenant_id,
                "u": url,
                "m": signing_mode,
                "ef": json.dumps(event_filter),
                "rp": json.dumps(retry_policy),
            },
        )
        row = result.fetchone()
        if hasattr(conn, "commit"):
            conn.commit()
    finally:
        _close(conn)

    return jsonify(_row_to_dict(row)), 201


@webhooks_bp.route("/<webhook_id>", methods=["DELETE"])
@auth_required
@require_scopes("gough.cluster.admin")
async def delete_webhook(webhook_id: str):
    """Delete a webhook endpoint owned by the caller's tenant."""
    tenant_id = _current_tenant()
    conn = _db_session()
    try:
        result = conn.execute(
            text(
                "DELETE FROM webhook_endpoints WHERE id = :i AND tenant_id = :t"
            ),
            {"i": webhook_id, "t": tenant_id},
        )
        if hasattr(conn, "commit"):
            conn.commit()
        rowcount = getattr(result, "rowcount", 0) or 0
    finally:
        _close(conn)
    if not rowcount:
        return jsonify({"error": "not_found"}), 404
    return ("", 204)


@webhooks_bp.route("/<webhook_id>/test", methods=["POST"])
@auth_required
@require_scopes("gough.cluster.admin")
async def test_webhook(webhook_id: str):
    """Dispatch a synthetic ``gough.webhook.test`` event."""
    tenant_id = _current_tenant()
    conn = _db_session()
    try:
        row = conn.execute(
            text(
                "SELECT id, tenant_id, url, signing_mode, active, event_filter, "
                "retry_policy FROM webhook_endpoints "
                "WHERE id = :i AND tenant_id = :t"
            ),
            {"i": webhook_id, "t": tenant_id},
        ).fetchone()
    finally:
        _close(conn)
    if row is None:
        return jsonify({"error": "not_found"}), 404
    record = _row_to_dict(row)

    endpoint = WebhookEndpoint(
        id=record["id"],
        tenant_id=record["tenant_id"],
        url=record["url"],
        signing_mode=record["signing_mode"],
        event_filter=tuple(record["event_filter"]),
        active=record["active"],
    )

    dispatcher = WebhookDispatcher(
        db_session=None,
        vault_client=_vault_client(),
        endpoint_loader=lambda _t: [endpoint],
    )
    try:
        results = await dispatcher.dispatch(
            {
                "type": "gough.webhook.test",
                "tenant_id": tenant_id,
                "data": {"endpoint_id": record["id"], "purpose": "configuration_test"},
            }
        )
    finally:
        await dispatcher.aclose()

    payload = [
        {
            "endpoint_id": r.endpoint_id,
            "event_id": r.event_id,
            "delivered": r.delivered,
            "attempts": r.attempts,
            "final_status": r.final_status,
            "final_error": r.final_error,
        }
        for r in results
    ]
    return jsonify({"results": payload}), 200


@webhooks_bp.route("/keys/<tenant>", methods=["GET"])
async def webhook_jwks(tenant: str):
    """Anonymous JWKS endpoint for consumer-side signature verification.

    Registered under ``ANONYMOUS_PATHS`` so no auth is required. Only
    asymmetric public keys (Ed25519, ECDSA P-256) are returned; HMAC keys
    are intentionally never exposed here.
    """
    if not tenant or len(tenant) > 128:
        return jsonify({"error": "invalid_tenant"}), 400
    try:
        jwks = _key_manager().get_jwks(tenant)
    except Exception:
        log.exception("failed to build JWKS for tenant %s", tenant)
        jwks = {"keys": []}
    resp = jsonify(jwks)
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp, 200


# ---------------------------------------------------------------------------
# Cleanup helper
# ---------------------------------------------------------------------------
def _close(conn: Any) -> None:
    closer = getattr(conn, "close", None)
    if callable(closer):
        try:
            closer()
        except Exception:  # pragma: no cover
            pass
