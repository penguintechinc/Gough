"""Audit Events REST API.

Per Gough spec Sprint 4 (Observability -> Audit Log Hash-Chain Format).

Endpoints:
  GET  /api/v1/audit/events     paginated, tenant-scoped query
  POST /api/v1/audit/verify     re-hashes the chain over [since, to]
  GET  /api/v1/audit/export     superadmin JSONL stream + Vault-signed footer

Chain integrity is the core deliverable: ``verify_chain`` is invoked exactly
as written in ``app.security.audit_chain``; on any break the Prometheus
counter ``gough_audit_chain_break_total`` is incremented before responding.

Export is a separate trust boundary — only ``gough.cluster.superadmin`` may
trigger it, MFA is mandatory in compliance lanes, and every export is itself
audit-logged with cross-referenced actor / target subjects so a future audit
sweep can trace which operator pulled which dataset.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Iterable, Optional

from prometheus_client import Counter
from quart import Blueprint, Response, current_app, g, jsonify, request
from quart import stream_with_context

from app.security.audit_chain import (
    AuditEventWriter,
    canonicalize_record,
    verify_chain,
)
from app.security.scope_enforcement import require_scopes
from app.security.tenant import set_tenant_guc

log = logging.getLogger(__name__)

audit_bp = Blueprint("audit", __name__)


# Module-level Prometheus counter — registered exactly once. Tests reset it
# via ``audit_chain_break_total._value.set(0)``.
audit_chain_break_total = Counter(
    "gough_audit_chain_break_total",
    "Audit hash-chain break detections",
    labelnames=("cluster_id",),
)


DEFAULT_MFA_REQUIRED_LANES: frozenset[str] = frozenset({"fedramp", "hipaa", "pci"})

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000


# =============================================================================
# Helpers
# =============================================================================


def _get_db_session() -> Any:
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
    tenant_ctx = g.get("tenant_context", None)
    if tenant_ctx is not None:
        return tenant_ctx.tenant_id
    principal = g.get("principal", None)
    if principal is not None:
        return principal.tenant_id
    raise PermissionError("tenant_context missing — request not authenticated")


def _get_actor_sub() -> str:
    principal = g.get("principal", None)
    if principal is not None:
        return principal.sub
    user = g.get("current_user", None)
    if user is not None:
        return str(user.get("sub") or user.get("email") or "unknown")
    return "unknown"


def _get_actor_scope() -> list[str]:
    principal = g.get("principal", None)
    if principal is not None:
        return sorted(principal.scopes)
    return []


def _is_super_admin() -> bool:
    principal = g.get("principal", None)
    if principal is None:
        return False
    return "gough.cluster.superadmin" in principal.scopes


def _mfa_required_for_tenant(tenant_id: str) -> bool:
    lane = current_app.config.get("TENANT_COMPLIANCE_LANE", {}).get(tenant_id)
    if lane is None:
        return False
    required = current_app.config.get(
        "COMPLIANCE_LANES_REQUIRING_MFA", DEFAULT_MFA_REQUIRED_LANES
    )
    return lane in required


def _request_has_mfa() -> bool:
    principal = g.get("principal", None)
    if principal is None:
        return False
    amr = principal.claims.get("amr") or []
    if isinstance(amr, str):
        amr = [amr]
    return any(m in {"mfa", "totp", "webauthn", "u2f", "hwk"} for m in amr)


def _parse_iso8601(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    # Accept Z suffix as +00:00
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def _serialize_audit_event(row: Any) -> dict[str, Any]:
    """Serialize a row from ``audit_events`` to JSON-safe dict.

    The hash, prev_hash, and signature columns are exposed (this is the audit
    surface; chain transparency is the point) but rendered as base64 so
    binary doesn't poison JSON streams.
    """

    def _b64(buf: Any) -> Optional[str]:
        if buf is None:
            return None
        if isinstance(buf, memoryview):
            buf = bytes(buf)
        if isinstance(buf, (bytes, bytearray)):
            return base64.b64encode(bytes(buf)).decode("ascii")
        return base64.b64encode(str(buf).encode("utf-8")).decode("ascii")

    return {
        "id": str(row.id),
        "ts": row.ts.isoformat() if row.ts else None,
        "cluster_id": row.cluster_id,
        "tenant_id": row.tenant_id,
        "actor_sub": row.actor_sub,
        "actor_scope": row.actor_scope or [],
        "action": row.action,
        "resource_kind": row.resource_kind,
        "resource_id": row.resource_id,
        "before_json": row.before_json,
        "after_json": row.after_json,
        "request_id": row.request_id,
        "source_ip": row.source_ip,
        "user_agent": row.user_agent,
        "prev_hash_b64": _b64(row.prev_hash),
        "hash_b64": _b64(row.hash),
        "signature_b64": _b64(row.signature),
    }


def _build_audit_writer(cluster_id: str) -> AuditEventWriter:
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
        db_session=_get_db_session(), cluster_id=cluster_id, signer=signer
    )


# =============================================================================
# Endpoints
# =============================================================================


@audit_bp.route("/events", methods=["GET"])
@require_scopes("gough.audit.read")
async def list_audit_events():
    """Paginated, tenant-scoped query over ``audit_events``."""
    from app.models_m1 import AuditEvent  # local import to avoid circulars

    tenant_id = _get_tenant_id()
    db = _get_db_session()
    set_tenant_guc(db, tenant_id)

    args = request.args
    since = _parse_iso8601(args.get("since"))
    until = _parse_iso8601(args.get("until"))
    actor_sub = args.get("actor_sub")
    action = args.get("action")
    resource_kind = args.get("resource_kind")
    resource_id = args.get("resource_id")
    request_id = args.get("request_id")
    cluster_id_filter = args.get("cluster_id")
    fmt = args.get("format", "json").lower()
    if fmt not in {"json", "jsonl"}:
        return (
            jsonify(
                {"error": "invalid_format", "allowed": ["json", "jsonl"]}
            ),
            400,
        )

    try:
        page_size = min(int(args.get("limit", DEFAULT_PAGE_SIZE)), MAX_PAGE_SIZE)
    except (TypeError, ValueError):
        page_size = DEFAULT_PAGE_SIZE
    cursor = args.get("cursor")

    query = db.query(AuditEvent).filter(AuditEvent.tenant_id == tenant_id)

    if cluster_id_filter:
        if not _is_super_admin():
            return (
                jsonify(
                    {
                        "error": "forbidden",
                        "message": (
                            "cluster_id filter requires gough.cluster.superadmin"
                        ),
                    }
                ),
                403,
            )
        query = query.filter(AuditEvent.cluster_id == cluster_id_filter)

    if since:
        query = query.filter(AuditEvent.ts >= since)
    if until:
        query = query.filter(AuditEvent.ts <= until)
    if actor_sub:
        query = query.filter(AuditEvent.actor_sub == actor_sub)
    if action:
        query = query.filter(AuditEvent.action == action)
    if resource_kind:
        query = query.filter(AuditEvent.resource_kind == resource_kind)
    if resource_id:
        query = query.filter(AuditEvent.resource_id == resource_id)
    if request_id:
        query = query.filter(AuditEvent.request_id == request_id)
    if cursor:
        try:
            cursor_uuid = uuid.UUID(cursor)
            query = query.filter(AuditEvent.id > cursor_uuid)
        except (TypeError, ValueError):
            return jsonify({"error": "invalid_cursor"}), 400

    rows = query.order_by(AuditEvent.id.asc()).limit(page_size + 1).all()
    has_more = len(rows) > page_size
    rows = rows[:page_size]
    next_cursor = str(rows[-1].id) if rows and has_more else None
    items = [_serialize_audit_event(r) for r in rows]

    if fmt == "jsonl":
        body_lines = [json.dumps(i, separators=(",", ":")) for i in items]
        body = "\n".join(body_lines) + ("\n" if body_lines else "")
        return Response(body, status=200, mimetype="application/x-ndjson")

    return (
        jsonify(
            {
                "tenant_id": tenant_id,
                "count": len(items),
                "next_cursor": next_cursor,
                "items": items,
            }
        ),
        200,
    )


@audit_bp.route("/verify", methods=["POST"])
@require_scopes("gough.audit.read")
async def verify_audit_chain():
    """Verify hash chain integrity over an optional time window."""
    body = await request.get_json(silent=True) or {}
    since = _parse_iso8601(body.get("since"))
    to = _parse_iso8601(body.get("to"))

    tenant_id = _get_tenant_id()
    db = _get_db_session()
    set_tenant_guc(db, tenant_id)

    result = verify_chain(db, since=since, to=to)

    cluster_id_label = current_app.config.get("CLUSTER_ID", "unknown")
    if result.get("breaks", 0) > 0:
        audit_chain_break_total.labels(cluster_id=cluster_id_label).inc(
            result["breaks"]
        )

    out = {
        "rows_checked": result["rows_checked"],
        "breaks": result["breaks"],
        "first_break_id": (
            str(result["first_break_id"]) if result.get("first_break_id") else None
        ),
        "last_break_id": (
            str(result["last_break_id"]) if result.get("last_break_id") else None
        ),
    }
    return jsonify(out), 200


def _stream_audit_events_jsonl(
    db: Any,
    cluster_id_label: str,
    target_sub: Optional[str],
    vault_client: Optional[Any],
    signing_key: str,
) -> Iterable[bytes]:
    """Synchronously yield JSONL bytes for the entire ``audit_events`` table.

    Each row is hashed (SHA-256 over JCS canonical form) into a rolling export
    digest. The final line is a Vault-transit signature over that digest so a
    downstream verifier can detect tampering during transport.
    """
    from app.models_m1 import AuditEvent

    rolling = hashlib.sha256()
    count = 0

    query = db.query(AuditEvent).order_by(AuditEvent.id.asc()).yield_per(500)
    for row in query:
        record = _serialize_audit_event(row)
        canonical = canonicalize_record(record)
        rolling.update(canonical)
        count += 1
        yield canonical + b"\n"

    digest = rolling.digest()

    if vault_client is not None:
        try:
            signature = vault_client.transit_sign(signing_key, digest)
        except Exception as exc:  # pragma: no cover — surfaced to footer
            signature = f"vault-sign-error:{exc}"
    else:
        signature = "unsigned"

    if isinstance(signature, bytes):
        signature_str = signature.decode("utf-8", errors="replace")
    else:
        signature_str = str(signature)

    footer = {
        "_signature": True,
        "rows_exported": count,
        "digest_b64": base64.b64encode(digest).decode("ascii"),
        "signing_key": signing_key,
        "signature": signature_str,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "cluster_id": cluster_id_label,
        "target_sub": target_sub,
    }
    yield (json.dumps(footer, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


@audit_bp.route("/export", methods=["GET"])
@require_scopes("gough.cluster.superadmin")
async def export_audit_log():
    """Stream audit log as JSONL with Vault-transit signed footer."""
    tenant_id = _get_tenant_id()
    mfa_block_required = _mfa_required_for_tenant(tenant_id) and not _request_has_mfa()
    if mfa_block_required:
        return (
            jsonify(
                {"error": "mfa_required", "message": "Compliance lane requires MFA"}
            ),
            401,
        )

    db = _get_db_session()
    set_tenant_guc(db, tenant_id)

    target_sub = request.args.get("target_sub")
    cluster_id_label = current_app.config.get("CLUSTER_ID", "unknown")
    signing_key = current_app.config.get(
        "AUDIT_EXPORT_SIGNING_KEY", "gough-audit-export"
    )
    vault_client = current_app.config.get("VAULT_CLIENT")

    actor_sub = _get_actor_sub()
    audit_writer = _build_audit_writer(cluster_id_label)
    audit_writer.append(
        actor_sub=actor_sub,
        actor_scope=_get_actor_scope(),
        action="audit.log.export",
        resource_kind="audit_log",
        tenant_id=tenant_id,
        after={
            "acting_sub": actor_sub,
            "target_sub": target_sub,
            "exported_at": datetime.now(timezone.utc).isoformat(),
        },
        request_id=request.headers.get("X-Request-Id"),
    )

    nats_client = current_app.config.get("NATS_CLIENT")
    if nats_client is not None:
        try:
            payload = json.dumps(
                {
                    "actor_sub": actor_sub,
                    "tenant_id": tenant_id,
                    "target_sub": target_sub,
                    "cluster_id": cluster_id_label,
                    "ts": datetime.now(timezone.utc).isoformat(),
                }
            ).encode("utf-8")
            nats_client.publish("gough.audit.exported", payload)
        except Exception:
            log.exception("Failed to publish gough.audit.exported NATS event")

    @stream_with_context
    async def _async_stream() -> AsyncIterator[bytes]:
        for chunk in _stream_audit_events_jsonl(
            db,
            cluster_id_label=cluster_id_label,
            target_sub=target_sub,
            vault_client=vault_client,
            signing_key=signing_key,
        ):
            yield chunk

    headers = {
        "Content-Type": "application/x-ndjson",
        "Content-Disposition": (
            f'attachment; filename="gough-audit-{cluster_id_label}.jsonl"'
        ),
    }
    return Response(_async_stream(), headers=headers, status=200)


__all__ = [
    "audit_bp",
    "audit_chain_break_total",
    "DEFAULT_MFA_REQUIRED_LANES",
    "_serialize_audit_event",
    "_stream_audit_events_jsonl",
]
