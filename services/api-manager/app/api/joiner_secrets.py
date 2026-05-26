"""Joiner Secrets REST API.

Per Gough spec Sprint 4 (Biome Model -> Joiner Secrets). All endpoints are
tenant-scoped; cluster-id from the URL is filtered against the JWT's tenant
claim through Layer 4 RLS (the GUC ``app.current_tenant`` is set by
``app.security.tenant.set_tenant_guc``).

Response payloads NEVER expose any portion of the encrypted envelope. The
fields ``ciphertext``, ``dek_wrapped``, ``iv``, and ``auth_tag`` are read
straight from the database for storage, but the API serializer in this module
explicitly redacts them — no caller, including ``gough.cluster.superadmin``,
can pull plaintext or wrapped DEK material through this surface. Plaintext
extraction is reserved for the gRPC ``Joiner.Consume`` RPC on a different
trust boundary.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from quart import Blueprint, current_app, g, jsonify, request

from app import metrics as _metrics

from app.models_m1 import JoinerSecret
from app.security.audit_chain import AuditEventWriter
from app.security.credentials import (
    CredentialError,
    InvalidCredentialError,
    validate_user_jwt,
)
from app.security.scope_enforcement import require_scopes
from app.security.tenant import set_tenant_guc
from app.workers.joiner_secret_emitter import (
    ExtractedMaterial,
    JoinerSecretEmitter,
)

log = logging.getLogger(__name__)

joiner_secrets_bp = Blueprint("joiner_secrets", __name__)

EXPIRING_SOON_WINDOW = timedelta(hours=24)

# Compliance lanes that mandate MFA for sensitive flows. Pulled from
# ``current_app.config["COMPLIANCE_LANES_REQUIRING_MFA"]`` if present so test
# fixtures and tenants can override; default mirrors the spec.
DEFAULT_MFA_REQUIRED_LANES: frozenset[str] = frozenset({"fedramp", "hipaa", "pci"})


# =============================================================================
# Helpers
# =============================================================================


def _get_db_session() -> Any:
    """Return the SQLAlchemy session attached to ``flask.g`` or the app.

    The Quart factory binds either ``g.db_session`` (request scope) or
    ``current_app.db_session_factory()`` for ad-hoc use. This wrapper is the
    single point of indirection so tests can monkey-patch ``g.db_session``.
    """
    sess = g.get("db_session", None)
    if sess is not None:
        return sess
    factory = current_app.config.get("DB_SESSION_FACTORY")
    if factory is None:
        raise RuntimeError("No DB session bound to request context")
    sess = factory()
    g.db_session = sess
    return sess


def _get_tenant_id() -> str:
    """Return the tenant id from the validated JWT context.

    The credentials middleware stores ``g.principal`` (Pydantic Principal); if
    fixtures pre-populate ``g.tenant_context`` directly, that path is honored.
    """
    tenant_ctx = g.get("tenant_context", None)
    if tenant_ctx is not None:
        return tenant_ctx.tenant_id
    principal = g.get("principal", None)
    if principal is not None:
        return principal.tenant_id
    raise PermissionError("tenant_context missing — request not authenticated")


def _get_actor_sub() -> str:
    """Return the actor sub for audit logging."""
    principal = g.get("principal", None)
    if principal is not None:
        return principal.sub
    user = g.get("current_user", None)
    if user is not None:
        return str(user.get("sub") or user.get("email") or "unknown")
    return "unknown"


def _get_actor_scope() -> list[str]:
    """Return the actor scopes for audit logging."""
    principal = g.get("principal", None)
    if principal is not None:
        return sorted(principal.scopes)
    return []


def _build_audit_writer(cluster_id: uuid.UUID) -> AuditEventWriter:
    """Construct an AuditEventWriter bound to the cluster + Vault transit signer."""
    vault_client = current_app.config.get("VAULT_CLIENT")
    signer = None
    if vault_client is not None:
        signing_key = current_app.config.get(
            "AUDIT_VAULT_SIGNING_KEY", "gough-audit-chain"
        )

        def _signer(record_hash: bytes) -> bytes:
            sig = vault_client.transit_sign(signing_key, record_hash)
            return sig.encode("utf-8") if isinstance(sig, str) else sig

        signer = _signer

    return AuditEventWriter(
        db_session=_get_db_session(),
        cluster_id=str(cluster_id),
        signer=signer,
    )


def _mfa_required_for_tenant(tenant_id: str) -> bool:
    """Return True when this tenant's compliance lane mandates MFA."""
    lane = current_app.config.get("TENANT_COMPLIANCE_LANE", {}).get(tenant_id)
    if lane is None:
        return False
    required = current_app.config.get(
        "COMPLIANCE_LANES_REQUIRING_MFA", DEFAULT_MFA_REQUIRED_LANES
    )
    return lane in required


def _request_has_mfa() -> bool:
    """Return True when the JWT carries an ``amr`` claim with MFA evidence."""
    principal = g.get("principal", None)
    if principal is None:
        return False
    amr = principal.claims.get("amr") or []
    if isinstance(amr, str):
        amr = [amr]
    return any(m in {"mfa", "totp", "webauthn", "u2f", "hwk"} for m in amr)


def _enforce_mfa_if_required(tenant_id: str) -> Optional[tuple[Any, int]]:
    """Return a 401 response if MFA is required but absent, else None."""
    if _mfa_required_for_tenant(tenant_id) and not _request_has_mfa():
        return (
            jsonify(
                {
                    "error": "mfa_required",
                    "tenant_id": tenant_id,
                    "message": "Compliance lane requires MFA for this action",
                }
            ),
            401,
        )
    return None


def _serialize_joiner_secret(row: JoinerSecret) -> dict[str, Any]:
    """Serialize a JoinerSecret row, omitting all envelope/secret material.

    Strict allow-list serialization. The fields ``ciphertext``, ``iv``,
    ``auth_tag``, and ``dek_wrapped`` are loaded into the ORM but MUST NEVER
    appear in API output. Tests assert this contract explicitly.
    """
    now = datetime.now(timezone.utc)
    revoked = row.revoked_at is not None
    expires_at = row.expires_at
    if revoked:
        status = "revoked"
    elif expires_at is not None and expires_at < now + EXPIRING_SOON_WINDOW:
        status = "expiring-soon"
    else:
        status = "active"
    expiring_soon = (
        not revoked
        and expires_at is not None
        and expires_at < now + EXPIRING_SOON_WINDOW
    )
    return {
        "id": str(row.id),
        "cluster_id": str(row.cluster_id),
        "tenant_id": row.tenant_id,
        "biome_kind": row.biome_kind,
        "emitter_biome_id": row.emitter_biome_id,
        "emitter_node_id": row.emitter_node_id,
        "extractor_name": row.extractor_name,
        "scope": row.scope,
        "vault_kek_name": row.vault_kek_name,
        "ttl_seconds": row.ttl_seconds,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "rotation_class": row.rotation_class,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "rotated_at": row.rotated_at.isoformat() if row.rotated_at else None,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        "audit_event_id": (
            str(row.audit_event_id) if row.audit_event_id else None
        ),
        "status": status,
        "expiring_soon": expiring_soon,
    }


# =============================================================================
# Endpoints
# =============================================================================


@joiner_secrets_bp.route(
    "/clusters/<uuid:cluster_id>/joiner-secrets", methods=["GET"]
)
@require_scopes("gough.joiner.read")
async def list_joiner_secrets(cluster_id: uuid.UUID):
    """List joiner secrets for a cluster (metadata only).

    Query params:
        biome_kind: optional filter
        scope: optional filter
        status: ``active|expiring-soon|revoked`` filter
    """
    tenant_id = _get_tenant_id()
    db = _get_db_session()
    set_tenant_guc(db, tenant_id)

    args = request.args
    biome_kind_filter = args.get("biome_kind")
    scope_filter = args.get("scope")
    status_filter = args.get("status")

    query = db.query(JoinerSecret).filter(
        JoinerSecret.cluster_id == cluster_id,
        JoinerSecret.tenant_id == tenant_id,
    )
    if biome_kind_filter:
        query = query.filter(JoinerSecret.biome_kind == biome_kind_filter)
    if scope_filter:
        query = query.filter(JoinerSecret.scope == scope_filter)

    rows = query.order_by(JoinerSecret.created_at.desc()).all()
    items = [_serialize_joiner_secret(r) for r in rows]

    if status_filter in {"active", "expiring-soon", "revoked"}:
        items = [i for i in items if i["status"] == status_filter]

    return (
        jsonify(
            {
                "cluster_id": str(cluster_id),
                "tenant_id": tenant_id,
                "count": len(items),
                "items": items,
            }
        ),
        200,
    )


@joiner_secrets_bp.route(
    "/clusters/<uuid:cluster_id>/joiner-secrets/<uuid:js_id>/rotate",
    methods=["POST"],
)
@require_scopes("gough.joiner.rotate")
async def rotate_joiner_secret(cluster_id: uuid.UUID, js_id: uuid.UUID):
    """Rotate a joiner secret: revoke old row + emit fresh secret."""
    tenant_id = _get_tenant_id()
    mfa_block = _enforce_mfa_if_required(tenant_id)
    if mfa_block is not None:
        return mfa_block

    body = await request.get_json(silent=True) or {}
    reason = body.get("reason")
    if not reason or not isinstance(reason, str) or not reason.strip():
        return (
            jsonify({"error": "missing_reason", "message": "reason is required"}),
            400,
        )

    db = _get_db_session()
    set_tenant_guc(db, tenant_id)

    row: Optional[JoinerSecret] = (
        db.query(JoinerSecret)
        .filter(
            JoinerSecret.id == js_id,
            JoinerSecret.cluster_id == cluster_id,
            JoinerSecret.tenant_id == tenant_id,
        )
        .one_or_none()
    )
    if row is None:
        return jsonify({"error": "not_found"}), 404
    if row.revoked_at is not None:
        return (
            jsonify(
                {
                    "error": "already_revoked",
                    "message": "cannot rotate a revoked secret",
                }
            ),
            409,
        )

    new_plaintext_provider = current_app.config.get(
        "JOINER_ROTATE_MATERIAL_PROVIDER"
    )
    if new_plaintext_provider is None:
        return (
            jsonify(
                {
                    "error": "rotation_provider_not_configured",
                    "message": (
                        "JOINER_ROTATE_MATERIAL_PROVIDER must return fresh "
                        "ExtractedMaterial for the emitter"
                    ),
                }
            ),
            503,
        )

    material: ExtractedMaterial = new_plaintext_provider(row)

    now = datetime.now(timezone.utc)
    row.revoked_at = now
    row.rotated_at = now
    db.flush()

    audit_writer = _build_audit_writer(cluster_id)
    actor_sub = _get_actor_sub()
    actor_scope = _get_actor_scope()
    request_id = request.headers.get("X-Request-Id")

    audit_writer.append(
        actor_sub=actor_sub,
        actor_scope=actor_scope,
        action="joiner.secret.rotate",
        resource_kind="joiner_secret",
        resource_id=str(row.id),
        tenant_id=tenant_id,
        before={"joiner_secret_id": str(row.id), "revoked_at": None},
        after={
            "joiner_secret_id": str(row.id),
            "revoked_at": now.isoformat(),
            "reason": reason,
        },
        request_id=request_id,
    )

    emitter = JoinerSecretEmitter(
        db_session=db,
        vault_client=current_app.config["VAULT_CLIENT"],
        audit_writer=audit_writer,
    )
    try:
        emit_result = emitter.emit(
            cluster_id=cluster_id,
            tenant_id=tenant_id,
            biome_kind=row.biome_kind,
            emitter_biome_id=row.emitter_biome_id,
            emitter_node_id=row.emitter_node_id,
            scope=row.scope,
            material=material,
            actor_sub=actor_sub,
            actor_scope=actor_scope,
            request_id=request_id,
        )
    except Exception:
        _metrics.joiner_secret_decryption_failure.inc()
        raise

    new_row = (
        db.query(JoinerSecret)
        .filter(JoinerSecret.id == emit_result.joiner_secret_id)
        .one()
    )

    return (
        jsonify(
            {
                "rotated": _serialize_joiner_secret(row),
                "new_secret": _serialize_joiner_secret(new_row),
                "audit_event_id": str(emit_result.audit_event_id),
            }
        ),
        201,
    )


@joiner_secrets_bp.route(
    "/clusters/<uuid:cluster_id>/joiner-secrets/<uuid:js_id>", methods=["DELETE"]
)
@require_scopes("gough.cluster.admin")
async def revoke_joiner_secret(cluster_id: uuid.UUID, js_id: uuid.UUID):
    """Revoke a joiner secret (sets ``revoked_at``; never hard-deletes)."""
    tenant_id = _get_tenant_id()
    body = await request.get_json(silent=True) or {}
    reason = body.get("reason")
    if not reason or not isinstance(reason, str) or not reason.strip():
        return (
            jsonify({"error": "missing_reason", "message": "reason is required"}),
            400,
        )

    db = _get_db_session()
    set_tenant_guc(db, tenant_id)

    row: Optional[JoinerSecret] = (
        db.query(JoinerSecret)
        .filter(
            JoinerSecret.id == js_id,
            JoinerSecret.cluster_id == cluster_id,
            JoinerSecret.tenant_id == tenant_id,
        )
        .one_or_none()
    )
    if row is None:
        return jsonify({"error": "not_found"}), 404
    if row.revoked_at is not None:
        return jsonify({"error": "already_revoked"}), 409

    now = datetime.now(timezone.utc)
    row.revoked_at = now
    db.flush()

    audit_writer = _build_audit_writer(cluster_id)
    audit_writer.append(
        actor_sub=_get_actor_sub(),
        actor_scope=_get_actor_scope(),
        action="joiner.secret.revoke",
        resource_kind="joiner_secret",
        resource_id=str(row.id),
        tenant_id=tenant_id,
        before={"revoked_at": None},
        after={"revoked_at": now.isoformat(), "reason": reason},
        request_id=request.headers.get("X-Request-Id"),
    )

    return jsonify({"revoked": _serialize_joiner_secret(row)}), 200


# Re-export for convenience in tests
__all__ = [
    "joiner_secrets_bp",
    "EXPIRING_SOON_WINDOW",
    "DEFAULT_MFA_REQUIRED_LANES",
    "_serialize_joiner_secret",
    "_mfa_required_for_tenant",
]


# Silence unused-import warnings for symbols re-exposed for fixture patching.
_ = (CredentialError, InvalidCredentialError, validate_user_jwt)
