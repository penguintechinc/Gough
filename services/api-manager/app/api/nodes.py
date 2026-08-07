"""Nodes & Discovery API Blueprint (Phase 1 — Spec: API Surface → Nodes & Discovery).

Endpoints
---------
POST   /api/v1/nodes/discover              anonymous (one-time bootstrap token)
GET    /api/v1/nodes                       gough.nodes.read
GET    /api/v1/nodes/{id}                  gough.nodes.read
PATCH  /api/v1/nodes/{id}                  gough.nodes.provision
POST   /api/v1/nodes/{id}/reject           gough.nodes.provision
POST   /api/v1/nodes/{id}/deploy           gough.nodes.provision
POST   /api/v1/nodes/{id}/evacuate         gough.nodes.provision
POST   /api/v1/nodes/{id}/events           service-SVID only (no user scopes)
DELETE /api/v1/nodes/{id}                  gough.nodes.decommission
GET    /api/v1/nodes/{id}/tags             gough.nodes.read
PATCH  /api/v1/nodes/{id}/tags             gough.nodes.provision

Legacy (Sprint 2 — retained for backward compat)
-------------------------------------------------
POST   /api/v1/nodes/{id}/biomes             gough.biomes.deploy
GET    /api/v1/nodes/{id}/biomes             gough.biomes.read
DELETE /api/v1/nodes/{id}/biomes/{biome_id}    gough.biomes.deploy
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import string
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from quart import Blueprint, Response, g, request, current_app

from ..db.run_db import run_db
from ..middleware import auth_required
from ..models import get_db
from ._biome_schema import NodeBiomeAssignRequest
from ._helpers import (
    EligibilityResult,
    check_tag_eligibility,
    envelope_error,
    envelope_success,
    err_bad_request,
    err_conflict,
    err_internal,
    err_not_found,
    err_validation,
    node_effective_tags,
    validate_body,
)
from ._schemas.nodes import (
    DecommissionRequest,
    DeployRequest,
    DiscoverRequest,
    EvacuateRequest,
    NodeEventRequest,
    NodePatchRequest,
    RejectRequest,
    TagsPatchRequest,
)

log = logging.getLogger(__name__)

nodes_bp = Blueprint("nodes", __name__, url_prefix="/api/v1/nodes")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VALID_NODE_STATES = frozenset(
    {
        "new",
        "probed",
        "planned",
        "deploying",
        "configuring",
        "ready",
        "upgrading",
        "quarantined",
        "draining",
        "decommissioned",
        "rejected",
    }
)

_TERMINAL_STATES = frozenset({"decommissioned", "rejected"})

# Default page size for cursor-based pagination
_DEFAULT_PAGE_SIZE = 50
_MAX_PAGE_SIZE = 500


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _g(row: Any, attr: str, default: Any = None) -> Any:
    """Tolerant attribute getter (ORM row or dict)."""
    try:
        return getattr(row, attr)
    except AttributeError:
        try:
            return row[attr]  # type: ignore[index]
        except (TypeError, KeyError):
            return default


def _serialize_node(node: Any, *, include_hw: bool = True) -> dict[str, Any]:
    """Serialise a node ORM row / dict to a JSON-safe payload."""
    out: dict[str, Any] = {
        "id": _g(node, "id"),
        "tenant_id": _g(node, "tenant_id", "__default__"),
        "name": _g(node, "name"),
        "state": _g(node, "state", "new"),
        "posture": _g(node, "posture", "compliant"),
        "dmi_uuid": _g(node, "dmi_uuid"),
        "primary_nic_mac": _g(node, "primary_nic_mac"),
        "ipv4": _g(node, "ipv4"),
        "ipv6": _g(node, "ipv6"),
        "ipv4_static": _g(node, "ipv4_static"),
        "firmware_type": _g(node, "firmware_type"),
        "boot_config_id": _g(node, "boot_config_id"),
        "preferred_addr_family": _g(node, "preferred_addr_family", "auto"),
        "attestation_method": _g(node, "attestation_method", "discovery_agent"),
        "discovered_at": _iso(_g(node, "discovered_at")),
        "deployed_at": _iso(_g(node, "deployed_at")),
        "created_at": _iso(_g(node, "created_at")),
        "updated_at": _iso(_g(node, "updated_at")),
    }
    if include_hw:
        out["hardware_json"] = _g(node, "hardware_json")
        out["hardware_tags"] = _g(node, "hardware_tags") or []
    return out


def _serialize_assignment(row: Any, *, biome: Any = None) -> dict[str, Any]:
    """Serialise a ``node_egg_assignments`` row to the public API shape.

    The physical table (gh-21) uses ``egg_id``/``depends_on_egg_instance_id``;
    the public API contract exposes these under their pre-existing
    ``biome_id``/``depends_on_biome_instance_id`` names.
    """
    return {
        "id": _g(row, "id"),
        "node_id": _g(row, "node_id"),
        "biome_id": _g(row, "egg_id"),
        "tenant_id": _g(row, "tenant_id"),
        "phase": _g(row, "phase"),
        "status": _g(row, "status"),
        "depends_on_biome_instance_id": _g(row, "depends_on_egg_instance_id"),
        "readiness_probe_state": _g(row, "readiness_probe_state", "not_started"),
        "assigned_at": _iso(_g(row, "assigned_at")),
        "deployed_at": _iso(_g(row, "deployed_at")),
        "removed_at": _iso(_g(row, "removed_at")),
        "biome": (
            {
                "id": biome.id,
                "name": _g(biome, "name"),
                "version": _g(biome, "version"),
                "biome_kind": _g(biome, "biome_kind", "custom"),
                "phase": _g(biome, "phase", "post_deploy"),
                "lock_to_host": _g(biome, "lock_to_host", False),
            }
            if biome is not None
            else None
        ),
    }


# ---------------------------------------------------------------------------
# Cursor-based pagination
# ---------------------------------------------------------------------------


def _encode_cursor(node_id: int, ts: datetime) -> str:
    """Encode (id, ts) tuple into a base64 opaque cursor string."""
    payload = json.dumps({"id": node_id, "ts": ts.isoformat()})
    return base64.urlsafe_b64encode(payload.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[int, datetime]:
    """Decode a cursor string back to (id, ts).  Raises ValueError on bad input."""
    try:
        payload = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        node_id = int(payload["id"])
        ts = datetime.fromisoformat(payload["ts"])
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return node_id, ts
    except Exception as exc:
        raise ValueError(f"Invalid cursor: {exc}") from exc


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _current_tenant_id() -> str:
    """Return the tenant_id from the current request context."""
    tc = g.get("tenant_context")
    if tc is not None:
        return getattr(tc, "tenant_id", "__default__")
    user = g.get("current_user") or {}
    payload = user.get("_jwt_payload") or {}
    return payload.get("tenant", "__default__")


def _is_cross_tenant() -> bool:
    """True iff the JWT carries cross_tenant=true (super-admin only)."""
    tc = g.get("tenant_context")
    if tc is not None:
        return bool(getattr(tc, "cross_tenant", False))
    user = g.get("current_user") or {}
    payload = user.get("_jwt_payload") or {}
    return bool(payload.get("cross_tenant", False))


def _actor_sub() -> str:
    user = g.get("current_user") or {}
    payload = user.get("_jwt_payload") or {}
    return payload.get("sub", str(user.get("id", "unknown")))


def _has_scope(scope: str) -> bool:
    user = g.get("current_user") or {}
    payload = user.get("_jwt_payload") or {}
    raw = payload.get("scope", "")
    if isinstance(raw, list):
        return scope in set(raw)
    return scope in set(raw.split())


# ---------------------------------------------------------------------------
# NATS publish helper (graceful no-op when NATS not wired)
# ---------------------------------------------------------------------------


async def _nats_publish_safe(subject: str, payload: dict[str, Any], tenant_id: str) -> None:
    """Publish to NATS; swallow all errors with a warning log."""
    try:
        from ..clients.nats import NatsClient  # type: ignore[import]

        client: Optional[NatsClient] = getattr(g, "nats_client", None)
        if client is None:
            # Try app-level singleton stored by factory
            from quart import current_app  # type: ignore[import]
            client = getattr(current_app, "nats_client", None)

        if client is None:
            log.warning("NATS client not wired; skipping publish on subject=%s", subject)
            return

        await client.publish(
            subject=subject,
            payload=payload,
            tenant_id=tenant_id,
            actor_sub=_actor_sub(),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("NATS publish failed (non-fatal) subject=%s error=%s", subject, exc)


# ---------------------------------------------------------------------------
# Audit helper (best-effort; does not fail the request)
# ---------------------------------------------------------------------------


def _audit_log(action: str, resource_id: str, *, before: Any = None, after: Any = None) -> None:
    """Write an audit event row if the audit_events table is available."""
    try:
        db = get_db()
        if not hasattr(db, "audit_events"):
            return
        import uuid as _uuid

        db.audit_events.insert(
            id=str(_uuid.uuid4()),
            ts=datetime.now(timezone.utc),
            cluster_id=os.getenv("GOUGH_CLUSTER_ID", "default"),
            tenant_id=_current_tenant_id(),
            actor_sub=_actor_sub(),
            action=action,
            resource_kind="node",
            resource_id=str(resource_id),
            before_json=before if before is None else json.dumps(before),
            after_json=after if after is None else json.dumps(after),
            request_id=request.headers.get("X-Request-ID", ""),
            source_ip=request.remote_addr or "",
        )
        db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("Audit log failed (non-fatal): %s", exc)


# ---------------------------------------------------------------------------
# POST /api/v1/nodes/discover  — anonymous (one-time bootstrap token)
# ---------------------------------------------------------------------------


@nodes_bp.route("/discover", methods=["POST"])
async def discover_node():
    """Phase-1 discovery endpoint.

    Called by the Go discovery-agent with a one-time bootstrap JWT.  The
    token must have been minted by ``POST /api/v1/ipxe/mint-bootstrap-token``
    and stored in Redis.  On success the agent receives a SPIRE join token and
    the address of the gRPC control tunnel.

    Identity conflict detection:
      - Same DMI UUID, different primary MAC → ``posture=identity_conflict``
      - Same primary MAC, different DMI UUID → ``posture=identity_conflict``
      Both cases emit ``gough.node.<id>.identity_conflict`` to NATS.
    """
    # ------------------------------------------------------------------
    # 1. Extract + validate the one-time bootstrap JWT
    # ------------------------------------------------------------------
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return envelope_error("unauthorized", "Bearer token required", 401)
    token = auth_header[7:]

    # Lazy import to avoid circular imports at module load
    from ..security.credentials import (
        validate_one_time_bootstrap_token,
        InvalidCredentialError,
        ExpiredCredentialError,
        OneTimeTokenReplayError,
    )

    # Resolve Redis client — graceful fallback to DB nonce store
    vault_client: Any = None
    redis_client: Any = None
    signing_secret: Optional[str] = None
    try:
        from quart import current_app  # type: ignore[import]
        vault_client = getattr(current_app, "vault_client", None)
        redis_client = getattr(current_app, "redis_client", None)
        # HS256-minted bootstrap tokens are verified with this shared secret;
        # Vault-transit-minted tokens are verified via vault_client. Without
        # either, the validator fails closed (no unverified decode path).
        signing_secret = current_app.config.get("JWT_SECRET_KEY") or current_app.config.get(
            "BOOTSTRAP_JWT_SECRET"
        )
    except Exception:  # noqa: BLE001
        pass

    if redis_client is None:
        # Minimal stub that delegates single-use enforcement to the DB table
        redis_client = _DbNonceStore(get_db())

    try:
        principal = validate_one_time_bootstrap_token(
            token=token,
            vault_client=vault_client,
            redis_client=redis_client,
            signing_secret=signing_secret,
        )
    except OneTimeTokenReplayError as exc:
        return envelope_error("conflict", f"Bootstrap token nonce already used: {exc.nonce}", 409)
    except ExpiredCredentialError as exc:
        return envelope_error("unauthorized", str(exc), 401)
    except InvalidCredentialError as exc:
        return envelope_error("unauthorized", str(exc), 401)
    except Exception as exc:  # noqa: BLE001
        log.exception("Bootstrap token validation error: %s", exc)
        return envelope_error("internal_error", "Token validation failed", 500)

    # ------------------------------------------------------------------
    # 2. Validate + parse the request body
    # ------------------------------------------------------------------
    raw = await request.get_json(silent=True)
    if raw is None:
        return err_bad_request("JSON body required")

    body, err_resp = validate_body(DiscoverRequest, raw)
    if err_resp is not None:
        return err_resp
    assert body is not None

    # ------------------------------------------------------------------
    # 3. Upsert the node row (match by dmi_uuid; detect identity conflicts)
    # ------------------------------------------------------------------
    db = get_db()
    tenant_id = "__default__"
    now = datetime.now(timezone.utc)

    identity_conflict = False

    existing_by_dmi = None
    existing_by_mac = None
    try:
        existing_by_dmi = db(db.nodes.dmi_uuid == body.dmi_uuid).select().first()
        existing_by_mac = db(
            db.nodes.primary_nic_mac == body.primary_nic_mac
        ).select().first()
    except Exception:  # noqa: BLE001 — table may be minimal on test DBs
        pass

    # Detect identity conflicts
    if existing_by_dmi and existing_by_mac:
        if _g(existing_by_dmi, "id") != _g(existing_by_mac, "id"):
            # MAC belongs to a *different* node than the DMI UUID
            identity_conflict = True
    elif existing_by_dmi and not existing_by_mac:
        # MAC changed for same DMI UUID — motherboard swap / NIC replacement
        existing_mac = _g(existing_by_dmi, "primary_nic_mac")
        if existing_mac and existing_mac != body.primary_nic_mac:
            identity_conflict = True
    elif existing_by_mac and not existing_by_dmi:
        # DMI UUID changed for same MAC — chassis swap
        existing_dmi = _g(existing_by_mac, "dmi_uuid")
        if existing_dmi and existing_dmi != body.dmi_uuid:
            identity_conflict = True

    posture = "identity_conflict" if identity_conflict else "compliant"

    # Build hardware JSON snapshot
    hardware_json: dict[str, Any] = {
        "firmware_type": body.firmware_type,
        "lshw": body.lshw_json,
        "lsblk": body.lsblk_json,
        "nics": [n.model_dump() for n in body.nics],
        "numa_topology": body.numa_topology.model_dump() if body.numa_topology else None,
        "accelerators": [a.model_dump() for a in body.accelerators],
        "smart_attributes": [s.model_dump() for s in body.smart_attributes],
    }

    try:
        existing = existing_by_dmi or existing_by_mac
        if existing:
            node_id = _g(existing, "id")
            update_kwargs: dict[str, Any] = {
                "primary_nic_mac": body.primary_nic_mac,
                "dmi_uuid": body.dmi_uuid,
                "hardware_json": hardware_json,
                "hardware_tags": body.hardware_tags,
                "posture": posture,
                "state": "probed",
                "discovered_at": now,
                "updated_at": now,
            }
            # Preserve firmware_type in node row if column exists
            try:
                db(db.nodes.id == node_id).update(**update_kwargs)
            except Exception:  # noqa: BLE001 — firmware_type column might not exist yet
                minimal = {k: v for k, v in update_kwargs.items() if k != "firmware_type"}
                db(db.nodes.id == node_id).update(**minimal)
        else:
            # New node — generate a sanitised name from the MAC
            name = f"node-{body.primary_nic_mac.replace(':', '')[-6:].lower()}"
            # Ensure uniqueness by appending UUID suffix if collision
            if db(db.nodes.name == name).select().first():
                name = f"{name}-{str(uuid.uuid4())[:8]}"

            insert_kwargs: dict[str, Any] = {
                "tenant_id": tenant_id,
                "name": name,
                "state": "probed",
                "dmi_uuid": body.dmi_uuid,
                "primary_nic_mac": body.primary_nic_mac,
                "posture": posture,
                "hardware_json": hardware_json,
                "hardware_tags": body.hardware_tags,
                "discovered_at": now,
                "created_at": now,
                "updated_at": now,
            }
            try:
                node_id = int(db.nodes.insert(**insert_kwargs))
            except Exception:  # noqa: BLE001 — missing optional columns
                minimal_insert = {
                    k: v
                    for k, v in insert_kwargs.items()
                    if k
                    in {
                        "tenant_id",
                        "name",
                        "state",
                        "dmi_uuid",
                        "primary_nic_mac",
                        "created_at",
                        "updated_at",
                    }
                }
                node_id = int(db.nodes.insert(**minimal_insert))

        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.exception("Error upserting node during discover: %s", exc)
        return envelope_error("internal_error", f"DB error during discover: {exc}", 500)

    # ------------------------------------------------------------------
    # 4. Emit identity_conflict NATS event when applicable
    # ------------------------------------------------------------------
    if identity_conflict:
        await _nats_publish_safe(
            subject=f"gough.node.{node_id}.identity_conflict",
            payload={
                "node_id": node_id,
                "dmi_uuid": body.dmi_uuid,
                "primary_nic_mac": body.primary_nic_mac,
                "conflict": "identity_conflict",
            },
            tenant_id=tenant_id,
        )
        # Also publish to machines state-changed topic
        await _nats_publish_safe(
            subject=f"gough.machines.{node_id}.state-changed",
            payload={
                "node_id": node_id,
                "state": "new",
                "event": "identity_conflict",
            },
            tenant_id=tenant_id,
        )

    # ------------------------------------------------------------------
    # 5. Issue a SPIRE join token for the node (helper phase)
    # ------------------------------------------------------------------
    spire_join_token: Optional[str] = None
    try:
        from ..clients.spire import SpireClient, SpireRegistrationEntry, SpireRegistrationFailed

        cluster_id = os.getenv("GOUGH_CLUSTER_ID", "default")
        trust_domain = os.getenv("GOUGH_SPIRE_TRUST_DOMAIN", f"gough.{cluster_id}")
        spire_agent_socket = os.getenv(
            "SPIRE_AGENT_SOCKET", "unix:///tmp/spire-agent/public/api.sock"
        )
        spire_server_address = os.getenv("SPIRE_SERVER_ADDRESS", "localhost:8081")

        spire = SpireClient(
            workload_api_socket=spire_agent_socket,
            server_address=spire_server_address,
        )

        spiffe_id = f"spiffe://{trust_domain}/node/helper/{body.dmi_uuid}"
        parent_id = f"spiffe://{trust_domain}/node"
        entry = SpireRegistrationEntry(
            spiffe_id=spiffe_id,
            parent_id=parent_id,
            selectors={"unix:uid": "0"},
            ttl_seconds=3600,
        )
        spire.register_workload(entry)
        # The join token is the SPIRE entry ID used as a short-lived credential.
        # In a full deployment the agent calls spire-server token generate; here
        # we return the entry_id as the join token — M2 wires the full token flow.
        spire_join_token = str(uuid.uuid4())  # placeholder join token for M1
        log.info("Issued SPIRE join token for node_id=%s dmi_uuid=%s", node_id, body.dmi_uuid)
    except Exception as exc:  # noqa: BLE001
        log.warning("SPIRE registration failed (non-fatal, M1): %s", exc)

    # ------------------------------------------------------------------
    # 6. Build response
    # ------------------------------------------------------------------
    cluster_id = os.getenv("GOUGH_CLUSTER_ID", "default")
    trust_domain = os.getenv("GOUGH_SPIRE_TRUST_DOMAIN", f"gough.{cluster_id}")
    control_tunnel_endpoint = os.getenv(
        "GOUGH_CONTROL_TUNNEL_ENDPOINT", "grpcs://api-manager:8443"
    )
    control_tunnel_spiffe_id = f"spiffe://{trust_domain}/api-manager"

    return envelope_success(
        {
            "node_id": node_id,
            "state": "probed",
            "spire_join_token": spire_join_token,
            "control_tunnel_endpoint": control_tunnel_endpoint,
            "control_tunnel_spiffe_id": control_tunnel_spiffe_id,
        },
        status_code=201,
    )


# ---------------------------------------------------------------------------
# Minimal DB-backed nonce store (fallback when Redis unavailable)
# ---------------------------------------------------------------------------


class _DbNonceStore:
    """Duck-type Redis SET/NX adapter backed by the bootstrap_nonces table.

    Only the ``set(key, value, ex=..., nx=True)`` call used by
    ``validate_one_time_bootstrap_token`` is emulated.
    """

    def __init__(self, db: Any) -> None:
        self._db = db

    def set(self, key: str, value: str, ex: int = 600, nx: bool = False) -> bool:  # noqa: A003
        """Return True if the key was newly set (nonce not yet used)."""
        nonce = key.removeprefix("bootstrap:nonce:")
        try:
            existing = self._db(
                self._db.bootstrap_nonces.nonce == nonce
            ).select().first()
            if existing:
                return False  # already used
            now = datetime.now(timezone.utc)
            from datetime import timedelta

            self._db.bootstrap_nonces.insert(
                nonce=nonce,
                mac="",
                phase="helper",
                used=True,
                issued_at=now,
                expires_at=now + timedelta(seconds=ex),
                used_at=now,
            )
            self._db.commit()
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("_DbNonceStore.set failed: %s", exc)
            # On any DB error, reject the token to be safe
            return False


# ---------------------------------------------------------------------------
# GET /api/v1/nodes — list with filtering + cursor pagination
# ---------------------------------------------------------------------------


@nodes_bp.route("/", methods=["GET"])
@auth_required
async def list_nodes():
    """List nodes with filtering and cursor-based pagination.

    Query parameters:
      state         (repeatable) filter by state
      tag           (repeatable) filter by hardware tag (exact match, AND)
      tenant_id     super-admin + cross_tenant=true only
      node_kind     reserved for future use (ignored in M1)
      name_contains case-insensitive substring match on name
      page_size     default 50, max 500
      cursor        opaque pagination cursor

    Regression: gh-22. The SELECT now runs off the event loop via
    ``run_db()`` -- this service is single-process/single-loop (gRPC
    shares it), so a synchronous, potentially page_size=500-row query here
    would stall every other request/RPC until it returned. Cursor
    filtering is still applied client-side over the fixed ``page_size + 1``
    window fetched below (unchanged, pre-existing behavior) -- a true
    DB-side seek past that window is out of scope for this sweep.
    """
    args = request.args
    db = get_db()
    tenant_id = _current_tenant_id()
    cross_tenant = _is_cross_tenant()

    # Tenant filter
    requested_tenant = args.get("tenant_id")
    if requested_tenant and not cross_tenant:
        return envelope_error(
            "forbidden_tenant",
            "tenant_id filter requires cross_tenant super-admin scope",
            403,
        )
    effective_tenant = requested_tenant if (requested_tenant and cross_tenant) else tenant_id

    # Parse page_size
    try:
        page_size = min(int(args.get("page_size", _DEFAULT_PAGE_SIZE)), _MAX_PAGE_SIZE)
        if page_size < 1:
            page_size = _DEFAULT_PAGE_SIZE
    except ValueError:
        return err_validation("page_size must be an integer")

    # Parse cursor
    cursor_raw = args.get("cursor")
    cursor_after_id: Optional[int] = None
    cursor_after_ts: Optional[datetime] = None
    if cursor_raw:
        try:
            cursor_after_id, cursor_after_ts = _decode_cursor(cursor_raw)
        except ValueError:
            return err_validation("cursor is invalid or tampered")

    # State filter
    states = [s for s in args.getlist("state") if s]
    for st in states:
        if st not in _VALID_NODE_STATES:
            return err_validation(f"Unknown state: {st}")

    # Tag filter
    tags = [t for t in args.getlist("tag") if t]
    name_contains = args.get("name_contains")

    # Build query
    try:
        conds = []
        table = db.nodes
        if not cross_tenant:
            conds.append(table.tenant_id == effective_tenant)
        if states:
            conds.append(table.state.belongs(states))
        if name_contains:
            conds.append(table.name.contains(name_contains))
        if tags:
            for tag in tags:
                conds.append(table.hardware_tags.contains([tag]))

        if conds:
            q: Any = conds[0]
            for c in conds[1:]:
                q = q & c
        else:
            q = table.id > 0  # select-all sentinel

        def _fetch() -> Any:
            return db(q).select(
                orderby=(table.created_at, table.id),
                limitby=(0, page_size + 1),
            )

        rows = await run_db(_fetch)
    except Exception as exc:  # noqa: BLE001
        log.exception("Error listing nodes: %s", exc)
        return envelope_error("internal_error", str(exc), 500)

    # Client-side cursor filtering (DB cursor would need SA expression; pyDAL
    # does not support tuple comparisons natively, so we filter in Python)
    if cursor_after_id is not None and cursor_after_ts is not None:
        filtered = []
        for row in rows:
            row_ts = _g(row, "created_at")
            if row_ts is None:
                continue
            if row_ts.tzinfo is None:
                row_ts = row_ts.replace(tzinfo=timezone.utc)
            if (row_ts, _g(row, "id")) > (cursor_after_ts, cursor_after_id):
                filtered.append(row)
        rows = filtered

    # Resolve next_cursor
    next_cursor: Optional[str] = None
    out_rows = list(rows)
    if len(out_rows) > page_size:
        out_rows = out_rows[:page_size]
        last = out_rows[-1]
        last_ts = _g(last, "created_at") or datetime.now(timezone.utc)
        if last_ts.tzinfo is None:
            last_ts = last_ts.replace(tzinfo=timezone.utc)
        next_cursor = _encode_cursor(_g(last, "id"), last_ts)

    serialised = [_serialize_node(r, include_hw=False) for r in out_rows]
    return envelope_success(
        {"nodes": serialised, "total": len(serialised)},
        next_cursor=next_cursor,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/nodes/{id} — full detail
# ---------------------------------------------------------------------------


@nodes_bp.route("/<int:node_id>", methods=["GET"])
@auth_required
async def get_node(node_id: int):
    """Return full node detail including hardware_json."""
    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    # Tenant isolation
    if not _is_cross_tenant():
        if _g(node, "tenant_id", "__default__") != _current_tenant_id():
            return err_not_found(f"Node {node_id} not found")

    return envelope_success({"node": _serialize_node(node)})


# ---------------------------------------------------------------------------
# PATCH /api/v1/nodes/{id} — JSON Merge Patch (RFC 7396)
# ---------------------------------------------------------------------------


@nodes_bp.route("/<int:node_id>", methods=["PATCH"])
@auth_required
async def patch_node(node_id: int):
    """Apply a JSON Merge Patch to allowed node fields.

    Allowed fields: name, ipv4_static, tenant_id (super-admin only).
    """
    raw = await request.get_json(silent=True)
    if raw is None:
        return err_bad_request("JSON body required")

    body, err_resp = validate_body(NodePatchRequest, raw)
    if err_resp is not None:
        return err_resp
    assert body is not None

    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    if not _is_cross_tenant():
        if _g(node, "tenant_id", "__default__") != _current_tenant_id():
            return err_not_found(f"Node {node_id} not found")

    # tenant_id move is super-admin only
    if body.tenant_id is not None and not _is_cross_tenant():
        return envelope_error(
            "forbidden_scope",
            "Moving tenant_id requires cross_tenant super-admin scope",
            403,
        )

    # Check for name collision
    if body.name is not None:
        collision = db(
            (db.nodes.name == body.name) & (db.nodes.id != node_id)
        ).select().first()
        if collision:
            return err_conflict("Node name already in use", details={"name": body.name})

    updates: dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    if body.name is not None:
        updates["name"] = body.name
    if body.ipv4_static is not None:
        updates["ipv4_static"] = body.ipv4_static
    if body.tenant_id is not None:
        updates["tenant_id"] = body.tenant_id

    if len(updates) == 1:  # only updated_at
        return envelope_success({"node": _serialize_node(node)})

    try:
        db(db.nodes.id == node_id).update(**updates)
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.exception("Error patching node %s: %s", node_id, exc)
        return err_internal(str(exc))

    refreshed = db(db.nodes.id == node_id).select().first()
    return envelope_success({"node": _serialize_node(refreshed)})


# ---------------------------------------------------------------------------
# POST /api/v1/nodes/{id}/reject
# ---------------------------------------------------------------------------


@nodes_bp.route("/<int:node_id>/reject", methods=["POST"])
@auth_required
async def reject_node(node_id: int):
    """Transition node probed → rejected (terminal state).

    Requires scope ``gough.nodes.provision``.  The transition is irreversible;
    further state changes require a full re-discovery.
    """
    raw = await request.get_json(silent=True)
    if raw is None:
        return err_bad_request("JSON body required")

    body, err_resp = validate_body(RejectRequest, raw)
    if err_resp is not None:
        return err_resp
    assert body is not None

    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    if not _is_cross_tenant():
        if _g(node, "tenant_id", "__default__") != _current_tenant_id():
            return err_not_found(f"Node {node_id} not found")

    current_state = _g(node, "state", "new")
    if current_state in _TERMINAL_STATES:
        return err_conflict(
            f"Node is already in terminal state '{current_state}'",
            details={"state": current_state},
        )
    if current_state not in {"new", "probed"}:
        return err_conflict(
            f"Node must be in 'new' or 'probed' state to reject (current: {current_state})",
            details={"state": current_state},
        )

    before = {"state": current_state}
    try:
        db(db.nodes.id == node_id).update(
            state="rejected",
            posture="rejected",
            updated_at=datetime.now(timezone.utc),
        )
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.exception("Error rejecting node %s: %s", node_id, exc)
        return err_internal(str(exc))

    _audit_log("node.reject", str(node_id), before=before, after={"state": "rejected", "reason": body.reason})
    return envelope_success(
        {"node_id": node_id, "state": "rejected", "reason": body.reason}
    )


# ---------------------------------------------------------------------------
# Helper: assignments table lookup
# ---------------------------------------------------------------------------


def _get_assignments_table(db: Any) -> tuple[Optional[Any], Optional[str]]:
    """Return the biome assignments table and its egg-id field name.

    ``node_egg_assignments`` is the only real, baseline-created assignments
    table (gh-21: ``node_biome_assignments`` was a phantom name that never
    existed as a table — the two-name preference/fallback this helper used
    to implement always resolved to ``node_egg_assignments`` in practice).
    Still returns ``(None, None)`` — rather than letting the
    ``TableNotFoundError`` propagate — for callers that degrade gracefully
    when the table isn't reflected (e.g. a minimal test DB).

    Returns: (table_object, field_name) where field_name is always 'egg_id'.
    """
    # penguin-dal raises TableNotFoundError on attribute access, so try-except instead
    try:
        return db.node_egg_assignments, "egg_id"
    except Exception:  # noqa: BLE001 — TableNotFoundError
        pass
    return None, None


# ---------------------------------------------------------------------------
# POST /api/v1/nodes/{id}/deploy
# ---------------------------------------------------------------------------


@nodes_bp.route("/<int:node_id>/deploy", methods=["POST"])
@auth_required
async def deploy_node(node_id: int):
    """Initiate a deployment plan for a node.

    Creates ``node_egg_assignments`` rows in ``pending`` state for each
    supplied biome and delegates compile + execution to ``app.workers.plan_compiler``
    (if importable).  Returns 202 immediately.

    Idempotency-Key header is required (X-Idempotency-Key).
    """
    idempotency_key = request.headers.get("X-Idempotency-Key")
    if not idempotency_key:
        return err_bad_request("X-Idempotency-Key header is required")

    raw = await request.get_json(silent=True)
    if raw is None:
        return err_bad_request("JSON body required")

    body, err_resp = validate_body(DeployRequest, raw)
    if err_resp is not None:
        return err_resp
    assert body is not None

    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    if not _is_cross_tenant():
        if _g(node, "tenant_id", "__default__") != _current_tenant_id():
            return err_not_found(f"Node {node_id} not found")

    current_state = _g(node, "state", "new")
    if current_state in _TERMINAL_STATES:
        return err_conflict(
            f"Cannot deploy a node in terminal state '{current_state}'",
            details={"state": current_state},
        )

    try:
        if hasattr(db, "disks"):
            failed_disks = db(
                (db.disks.node_id == node_id)
                & (db.disks.smart_status == "failed")
            ).select()
            if failed_disks:
                return envelope_error(
                    "conflict",
                    f"Node {node_id} has failed SMART status; provisioning blocked until disks are replaced or status cleared by operator.",
                    409,
                )
    except Exception as exc:  # noqa: BLE001
        log.warning("SMART status check failed (non-fatal): %s", exc)

    # Validate biome IDs exist
    assignment_ids: list[int] = []
    now = datetime.now(timezone.utc)
    tenant_id = _g(node, "tenant_id", "__default__")

    assign_tbl, biome_field = _get_assignments_table(db)
    if not assign_tbl:
        return err_internal("node_egg_assignments table not available")

    try:
        for spec in body.biome_assignments:
            biome = db(db.biomes.id == spec.biome_id).select().first() if hasattr(db, "biomes") else None
            if not biome:
                return err_not_found(f"Biome {spec.biome_id} not found")

            # Skip if already pending/deploying/ready
            existing = db(
                (assign_tbl.node_id == node_id)
                & (getattr(assign_tbl, biome_field) == spec.biome_id)
                & (
                    assign_tbl.status.belongs(
                        ["pending", "deploying", "ready", "draining"]
                    )
                )
            ).select().first()
            if existing:
                assignment_ids.append(int(_g(existing, "id")))
                continue

            # Build insert dict with the correct field names
            # Map biome field names: biome_id → egg_id, depends_on_biome_instance_id → depends_on_egg_instance_id
            depends_field = "depends_on_egg_instance_id" if biome_field == "egg_id" else "depends_on_biome_instance_id"
            insert_data = {
                "node_id": node_id,
                biome_field: spec.biome_id,
                "tenant_id": tenant_id,
                "phase": spec.phase or _g(biome, "phase", "post_deploy"),
                "status": "pending",
                depends_field: spec.depends_on_biome_instance_id,
                "readiness_probe_state": "not_started",
                "assigned_at": now,
                "created_at": now,
                "updated_at": now,
            }
            new_id = assign_tbl.insert(**insert_data)
            assignment_ids.append(int(new_id))

        db.commit()
    except Exception as exc:  # noqa: BLE001
        log.exception("Error creating biome assignments for node %s: %s", node_id, exc)
        return err_internal(str(exc))

    # Wire plan compiler (Phase B; FIX: use PlanCompiler.compile directly).
    # PlanCompiler is synchronous; wrap in asyncio.to_thread to avoid blocking.
    compiler_invoked = False
    compiler_note = "Plan compile queued; worker will process asynchronously."
    try:
        from ..workers.plan_compiler import PlanCompiler, PlanCompilationError  # type: ignore[import]
        import asyncio

        # TODO(Phase B): Inject vault_client, lxd_client, spire_client from app config
        # For now, instantiate with minimal dependencies and handle gracefully.
        compiler = PlanCompiler(
            db_session=db,
            vault_client=None,
            lxd_client=None,
            spire_client=None,
        )
        # TODO(Phase B): Build PlanRequest from body + context; call compiler.compile()
        # For now, just note that the infrastructure is ready but incomplete.
        log.info("Plan compiler wired but incomplete (Phase B work); skipping invocation for node_id=%s", node_id)
        compiler_invoked = False
        compiler_note = "Plan compile not yet wired (Phase B work pending)."
    except ImportError:
        log.debug("plan_compiler module not available (expected during Wave 1)")
    except Exception as exc:  # noqa: BLE001
        log.warning("plan_compiler initialization failed (non-fatal): %s", exc)

    _audit_log(
        "node.deploy",
        str(node_id),
        after={"biome_assignments": [s.model_dump() for s in body.biome_assignments]},
    )
    for aid in assignment_ids:
        await _nats_publish_safe(
            subject=f"gough.deployments.{aid}.status-changed",
            payload={"deployment_id": aid, "node_id": node_id, "status": "pending"},
            tenant_id=tenant_id,
        )
    return envelope_success(
        {
            "node_id": node_id,
            "assignment_ids": assignment_ids,
            "state": current_state,
            "compiler_invoked": compiler_invoked,
            "note": compiler_note,
        },
        status_code=202,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/nodes/{id}/evacuate
# ---------------------------------------------------------------------------


@nodes_bp.route("/<int:node_id>/evacuate", methods=["POST"])
@auth_required
async def evacuate_node(node_id: int):
    """Begin evacuation of all non-pinned biomes from a node.

    In M1, validates the safety envelope via
    ``app.workers.migration_engine.evaluate_safety`` if importable, then
    returns 202.  Actual migration executes asynchronously.
    """
    raw = await request.get_json(silent=True)
    if raw is None:
        raw = {}
    body, err_resp = validate_body(EvacuateRequest, raw)
    if err_resp is not None:
        return err_resp
    assert body is not None

    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    if not _is_cross_tenant():
        if _g(node, "tenant_id", "__default__") != _current_tenant_id():
            return err_not_found(f"Node {node_id} not found")

    current_state = _g(node, "state", "new")
    if current_state in _TERMINAL_STATES:
        return err_conflict(
            f"Cannot evacuate a node in terminal state '{current_state}'",
            details={"state": current_state},
        )

    # Evaluate safety envelope
    safety_ok = True
    safety_note = "Safety envelope evaluated successfully."
    try:
        from ..workers.migration_engine import evaluate_safety
        result = await evaluate_safety(node_id=node_id)
        safety_ok = bool(result.get("safe", True))
        safety_note = result.get("note", "")
    except Exception as exc:  # noqa: BLE001
        log.warning("evaluate_safety raised: %s", exc)
        safety_note = f"Safety envelope check failed: {exc}"
        safety_ok = False

    if not safety_ok and not body.force:
        return envelope_error(
            "conflict",
            f"Safety envelope check failed: {safety_note}",
            409,
            details={"safe": False, "note": safety_note},
        )

    _audit_log(
        "node.evacuate",
        str(node_id),
        after={"reason": body.reason, "force": body.force},
    )
    return envelope_success(
        {
            "node_id": node_id,
            "safety_ok": safety_ok,
            "force": body.force,
            "note": safety_note or "Evacuation queued; migration worker will execute.",
        },
        status_code=202,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/nodes/{id}/events — service-SVID only
# ---------------------------------------------------------------------------


@nodes_bp.route("/<int:node_id>/events", methods=["POST"])
async def post_node_event(node_id: int):
    """Accept progress events from the discovery-agent or cloud-init steps.

    Authentication: service-SVID (mTLS X.509) with SPIFFE ID matching
    ``spiffe://gough.*/node/.*``.  User JWTs are rejected.

    Persists a ``node_events`` row and republishes to NATS subject
    ``gough.node.{id}.events``.
    """
    # Validate service SVID
    peer_cert_pem: Optional[str] = getattr(request, "peer_cert_pem", None)
    if peer_cert_pem is None:
        return envelope_error(
            "unauthorized",
            "Service SVID (mTLS client certificate) required for this endpoint",
            401,
        )
    else:
        from ..security.credentials import validate_service_svid, InvalidCredentialError

        trust_bundle_pem: Optional[str] = None
        try:
            from quart import current_app  # type: ignore[import]
            trust_bundle_pem = getattr(current_app, "spire_trust_bundle", None)
        except Exception:  # noqa: BLE001
            pass

        if trust_bundle_pem is None:
            trust_bundle_pem = os.getenv("GOUGH_SPIRE_TRUST_BUNDLE", "")

        spiffe_pattern = re.compile(r"spiffe://gough\.[^/]+/node/.*")
        try:
            from ..security.credentials import validate_service_svid

            principal = validate_service_svid(
                peer_cert_pem=peer_cert_pem,
                trust_bundle_pem=trust_bundle_pem,
                allowed_spiffe_ids=frozenset(),  # pattern checked below
            )
            if not spiffe_pattern.match(principal.spiffe_id or ""):
                return envelope_error(
                    "forbidden_scope",
                    f"SPIFFE ID {principal.spiffe_id!r} does not match node pattern",
                    403,
                )
        except InvalidCredentialError as exc:
            return envelope_error("unauthorized", str(exc), 401)

    raw = await request.get_json(silent=True)
    if raw is None:
        return err_bad_request("JSON body required")

    body, err_resp = validate_body(NodeEventRequest, raw)
    if err_resp is not None:
        return err_resp
    assert body is not None

    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    now = datetime.now(timezone.utc)
    event_ts: datetime
    if body.timestamp:
        try:
            event_ts = datetime.fromisoformat(body.timestamp)
            if event_ts.tzinfo is None:
                event_ts = event_ts.replace(tzinfo=timezone.utc)
        except ValueError:
            event_ts = now
    else:
        event_ts = now

    # Persist to node_events table
    event_id: Optional[int] = None
    try:
        if hasattr(db, "node_events"):
            row_data: dict[str, Any] = {
                "node_id": node_id,
                "ts": event_ts,
                "stage": body.stage,
                "message": body.message,
                "progress_pct": body.progress_pct,
                "raw_json": json.dumps(raw),
            }
            event_id = int(db.node_events.insert(**row_data))
            db.commit()
        else:
            log.info(
                "node_events table not yet migrated; logging event inline: "
                "node_id=%s stage=%s message=%s",
                node_id,
                body.stage,
                body.message,
            )
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.exception("Error persisting node event for node %s: %s", node_id, exc)
        return err_internal(str(exc))

    tenant_id = _g(node, "tenant_id", "__default__")
    try:
        await _nats_publish_safe(
            subject=f"gough.node.{node_id}.events",
            payload={
                "node_id": node_id,
                "stage": body.stage,
                "message": body.message,
                "progress_pct": body.progress_pct,
                "ts": event_ts.isoformat(),
            },
            tenant_id=tenant_id,
        )
        await _nats_publish_safe(
            subject=f"gough.machines.{node_id}.state-changed",
            payload={
                "node_id": node_id,
                "stage": body.stage,
                "message": body.message,
                "progress_pct": body.progress_pct,
                "ts": event_ts.isoformat(),
            },
            tenant_id=tenant_id,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("NATS event publish failed (non-fatal) node_id=%s error=%s", node_id, exc)

    return envelope_success(
        {
            "event_id": event_id,
            "node_id": node_id,
            "stage": body.stage,
            "ts": event_ts.isoformat(),
        },
        status_code=201,
    )


# ---------------------------------------------------------------------------
# DELETE /api/v1/nodes/{id} — soft decommission
# ---------------------------------------------------------------------------


@nodes_bp.route("/<int:node_id>", methods=["DELETE"])
@auth_required
async def decommission_node(node_id: int):
    """Soft-delete a node (state → decommissioned).

    Requires scope ``gough.nodes.decommission``.  The ``reason`` field is
    mandatory.  The operation is audit-logged.
    """
    raw = await request.get_json(silent=True)
    if raw is None:
        return err_bad_request("JSON body with 'reason' required")

    body, err_resp = validate_body(DecommissionRequest, raw)
    if err_resp is not None:
        return err_resp
    assert body is not None

    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    if not _is_cross_tenant():
        if _g(node, "tenant_id", "__default__") != _current_tenant_id():
            return err_not_found(f"Node {node_id} not found")

    current_state = _g(node, "state", "new")
    if current_state == "decommissioned":
        return err_conflict("Node is already decommissioned", details={"state": current_state})

    before = {"state": current_state}
    try:
        db(db.nodes.id == node_id).update(
            state="decommissioned",
            updated_at=datetime.now(timezone.utc),
        )
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.exception("Error decommissioning node %s: %s", node_id, exc)
        return err_internal(str(exc))

    _audit_log(
        "node.decommission",
        str(node_id),
        before=before,
        after={"state": "decommissioned", "reason": body.reason},
    )
    return envelope_success(
        {"node_id": node_id, "state": "decommissioned", "reason": body.reason}
    )


# ---------------------------------------------------------------------------
# GET /api/v1/nodes/{id}/tags
# ---------------------------------------------------------------------------


@nodes_bp.route("/<int:node_id>/tags", methods=["GET"])
@auth_required
async def get_node_tags(node_id: int):
    """Return the merged effective tag set with per-tag provenance.

    ``provenance`` is ``"auto"`` for hardware-discovered tags and
    ``"operator"`` for operator-defined ones.  Operator wins on key collision.
    """
    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    if not _is_cross_tenant():
        if _g(node, "tenant_id", "__default__") != _current_tenant_id():
            return err_not_found(f"Node {node_id} not found")

    # Auto tags
    auto_raw = _g(node, "hardware_tags") or []
    auto_tags: list[dict[str, Any]] = []
    if isinstance(auto_raw, list):
        for t in auto_raw:
            if isinstance(t, str) and t.strip():
                auto_tags.append({"tag": t.strip(), "provenance": "auto"})

    # Operator tags — query node_tags_operator table
    operator_tags: list[dict[str, Any]] = []
    operator_keys: set[str] = set()
    try:
        if hasattr(db, "node_tags_operator"):
            rows = db(db.node_tags_operator.node_id == node_id).select()
            for row in rows:
                k = _g(row, "tag_key", "")
                v = _g(row, "tag_value", "")
                if k:
                    tag_str = f"{k}:{v}" if v else k
                    operator_tags.append(
                        {
                            "tag": tag_str,
                            "tag_key": k,
                            "tag_value": v,
                            "provenance": "operator",
                            "set_by": _g(row, "set_by_actor_sub"),
                            "set_at": _iso(_g(row, "set_at")),
                        }
                    )
                    operator_keys.add(k)
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not fetch operator tags for node %s: %s", node_id, exc)

    # Suppress auto tags whose key is shadowed by an operator tag
    merged_auto = [
        t for t in auto_tags if t["tag"].split(":")[0] not in operator_keys
    ]

    all_tags = merged_auto + operator_tags
    return envelope_success({"tags": all_tags, "total": len(all_tags)})


# ---------------------------------------------------------------------------
# PATCH /api/v1/nodes/{id}/tags
# ---------------------------------------------------------------------------


@nodes_bp.route("/<int:node_id>/tags", methods=["PATCH"])
@auth_required
async def patch_node_tags(node_id: int):
    """Add or remove operator-defined tags on a node.

    Only the ``node_tags_operator`` table is mutated.  Auto-discovered
    ``hardware_tags`` are read-only.

    Body: ``{add: [{tag_key, tag_value}], remove: [{tag_key, tag_value}]}``.
    """
    raw = await request.get_json(silent=True)
    if raw is None:
        return err_bad_request("JSON body required")

    body, err_resp = validate_body(TagsPatchRequest, raw)
    if err_resp is not None:
        return err_resp
    assert body is not None

    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    if not _is_cross_tenant():
        if _g(node, "tenant_id", "__default__") != _current_tenant_id():
            return err_not_found(f"Node {node_id} not found")

    actor = _actor_sub()
    tenant_id = _g(node, "tenant_id", "__default__")
    now = datetime.now(timezone.utc)

    try:
        # Removes first
        for entry in body.remove:
            if hasattr(db, "node_tags_operator"):
                db(
                    (db.node_tags_operator.node_id == node_id)
                    & (db.node_tags_operator.tag_key == entry.tag_key)
                    & (db.node_tags_operator.tag_value == entry.tag_value)
                ).delete()

        # Adds (upsert: insert if not exists)
        for entry in body.add:
            if hasattr(db, "node_tags_operator"):
                existing = db(
                    (db.node_tags_operator.node_id == node_id)
                    & (db.node_tags_operator.tag_key == entry.tag_key)
                    & (db.node_tags_operator.tag_value == entry.tag_value)
                ).select().first()
                if not existing:
                    db.node_tags_operator.insert(
                        node_id=node_id,
                        tenant_id=tenant_id,
                        tag_key=entry.tag_key,
                        tag_value=entry.tag_value,
                        provenance="operator",
                        set_by_actor_sub=actor,
                        set_at=now,
                    )

        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.exception("Error patching tags for node %s: %s", node_id, exc)
        return err_internal(str(exc))

    _audit_log(
        "node.tags.patch",
        str(node_id),
        after={
            "add": [e.model_dump() for e in body.add],
            "remove": [e.model_dump() for e in body.remove],
        },
    )

    # Return updated effective tag set
    return await get_node_tags(node_id)


# ===========================================================================
# Legacy Sprint-2 biome-assignment sub-routes (retained for backward compat)
# ===========================================================================


@nodes_bp.route("/<int:node_id>/biomes", methods=["POST"])
@auth_required
async def assign_biome_to_node(node_id: int):
    """Assign a biome to a node's plan (Sprint 2 — retained)."""
    raw = await request.get_json(silent=True)
    if raw is None:
        return err_bad_request("JSON body required")
    body, err = validate_body(NodeBiomeAssignRequest, raw)
    if err is not None:
        return err
    assert body is not None

    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    # Tenant isolation (FIX #7b): guard node ownership
    if not _is_cross_tenant():
        if _g(node, "tenant_id", "__default__") != _current_tenant_id():
            return err_not_found(f"Node {node_id} not found")

    biome = db(db.biomes.id == body.biome_id).select().first() if hasattr(db, "biomes") else None
    if not biome:
        return err_not_found(f"Biome {body.biome_id} not found")

    assign_tbl, biome_field = _get_assignments_table(db)
    if not assign_tbl:
        return err_internal("node_egg_assignments table not available")

    existing = db(
        (assign_tbl.node_id == node_id)
        & (getattr(assign_tbl, biome_field) == body.biome_id)
        & (
            assign_tbl.status.belongs(
                ["pending", "deploying", "ready", "draining"]
            )
        )
    ).select().first()
    if existing:
        return err_conflict(
            "Biome already assigned to this node",
            details={"assignment_id": _g(existing, "id"), "status": _g(existing, "status")},
        )

    res: EligibilityResult = check_tag_eligibility(
        _g(biome, "requires_hardware_tags") or [],
        _g(biome, "forbids_hardware_tags") or [],
        node_effective_tags(db, node),
    )
    if not res.eligible:
        return envelope_error(
            "tag_constraint_unsatisfiable",
            "Node does not satisfy biome hardware-tag constraints",
            422,
            details=res.to_dict(),
        )

    if body.depends_on_biome_instance_id is not None:
        dep = db(assign_tbl.id == body.depends_on_biome_instance_id).select().first()
        if not dep:
            return err_validation(
                "depends_on_biome_instance_id references a missing assignment",
                violations=[
                    {
                        "field": "depends_on_biome_instance_id",
                        "code": "not_found",
                        "message": f"assignment {body.depends_on_biome_instance_id} not found",
                    }
                ],
            )

    try:
        # Map field names for backward-compat: egg_id → biome_id, depends_on_egg_instance_id → depends_on_biome_instance_id
        depends_field = "depends_on_egg_instance_id" if biome_field == "egg_id" else "depends_on_biome_instance_id"
        # ``created_at``/``updated_at`` are NOT NULL on the real
        # ``node_egg_assignments`` table with no server-side default (gh-21
        # regression: this insert used to omit them entirely, which never
        # surfaced against the phantom-table test fixtures' laxer
        # constraints -- against real Postgres it's a NotNullViolation).
        now = datetime.now(timezone.utc)
        insert_data = {
            "node_id": node_id,
            biome_field: body.biome_id,
            "tenant_id": _g(node, "tenant_id", "__default__"),
            "phase": body.phase,
            "status": "pending",
            depends_field: body.depends_on_biome_instance_id,
            "readiness_probe_state": "not_started",
            "assigned_at": now,
            "created_at": now,
            "updated_at": now,
        }
        new_id = assign_tbl.insert(**insert_data)
        db.commit()
    except Exception as exc:  # noqa: BLE001
        log.exception("Error assigning biome %s to node %s: %s", body.biome_id, node_id, exc)
        return err_internal(str(exc))

    row = db(assign_tbl.id == new_id).select().first()
    return envelope_success({"assignment": _serialize_assignment(row, biome=biome)}, status_code=201)


@nodes_bp.route("/<int:node_id>/biomes", methods=["GET"])
@auth_required
async def list_node_biomes(node_id: int):
    """List biome assignments for a node (Sprint 2 — retained)."""
    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    # Tenant isolation (FIX #7b): guard node ownership
    if not _is_cross_tenant():
        if _g(node, "tenant_id", "__default__") != _current_tenant_id():
            return err_not_found(f"Node {node_id} not found")

    assign_tbl, biome_field = _get_assignments_table(db)
    if not assign_tbl:
        return envelope_success({"assignments": [], "total": 0})

    statuses = [s for s in request.args.getlist("status") if s]
    q = assign_tbl.node_id == node_id
    if statuses:
        q = q & assign_tbl.status.belongs(statuses)
    rows = db(q).select(orderby=assign_tbl.assigned_at)

    out: list[dict] = []
    for row in rows:
        biome_id = _g(row, biome_field)
        biome = db(db.biomes.id == biome_id).select().first() if hasattr(db, "biomes") and biome_id else None
        out.append(_serialize_assignment(row, biome=biome))
    return envelope_success({"assignments": out, "total": len(out)})


@nodes_bp.route("/<int:node_id>/biomes/<int:biome_id>", methods=["DELETE"])
@auth_required
async def unassign_biome_from_node(node_id: int, biome_id: int):
    """Unassign a biome from a node (Sprint 2 — retained)."""
    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    # Tenant isolation (FIX #7b): guard node ownership
    if not _is_cross_tenant():
        if _g(node, "tenant_id", "__default__") != _current_tenant_id():
            return err_not_found(f"Node {node_id} not found")

    assign_tbl, biome_field = _get_assignments_table(db)
    if not assign_tbl:
        return err_not_found(f"No active assignment for biome {biome_id} on node {node_id}")

    row = db(
        (assign_tbl.node_id == node_id)
        & (getattr(assign_tbl, biome_field) == biome_id)
        & (
            assign_tbl.status.belongs(
                ["pending", "deploying", "ready"]
            )
        )
    ).select().first()
    if not row:
        return err_not_found(f"No active assignment for biome {biome_id} on node {node_id}")

    try:
        db(assign_tbl.id == row.id).update(
            status="draining",
            removed_at=datetime.now(timezone.utc),
        )
        db.commit()
    except Exception as exc:  # noqa: BLE001
        log.exception("Error unassigning biome %s from node %s: %s", biome_id, node_id, exc)
        return err_internal(str(exc))

    return envelope_success(
        {
            "assignment_id": _g(row, "id"),
            "status": "draining",
            "note": "Drain executes asynchronously; migration worker handles teardown.",
        },
        status_code=202,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/nodes/{id}/cloud-init
# ---------------------------------------------------------------------------


@nodes_bp.route("/<int:node_id>/cloud-init", methods=["GET"])
@auth_required
async def get_node_cloud_init(node_id: int) -> Any:
    """Return rendered cloud-init user-data for a node.

    Uses the default cloud_init_templates row and substitutes $node_id,
    $hostname, and $baseline (query param: native|hybrid|full-virtual, default native)
    via string.Template.
    """
    from quart import request as _req

    _VALID_BASELINES = {"native", "hybrid", "full-virtual"}
    baseline = (_req.args.get("baseline") or "native").lower()
    if baseline not in _VALID_BASELINES:
        return err_bad_request(f"Invalid baseline; must be one of: {', '.join(sorted(_VALID_BASELINES))}")

    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    if not _is_cross_tenant():
        if _g(node, "tenant_id", "__default__") != _current_tenant_id():
            return err_not_found(f"Node {node_id} not found")

    template_row = None
    try:
        if hasattr(db, "cloud_init_templates"):
            template_row = db(
                db.cloud_init_templates.is_default == True  # noqa: E712
            ).select().first()
    except Exception as exc:  # noqa: BLE001
        log.warning("Error querying cloud_init_templates: %s", exc)

    if template_row is None:
        return err_not_found("No default cloud-init template configured")

    hostname = _g(node, "name") or str(node_id)
    content = _g(template_row, "template_content") or ""

    try:
        rendered = string.Template(content).safe_substitute(
            node_id=str(node_id),
            hostname=hostname,
            baseline=baseline,
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("cloud-init template substitution failed for node %s: %s", node_id, exc)
        return err_internal(f"Template render error: {exc}")

    return Response(rendered, status=200, content_type="text/plain; charset=utf-8")


# ---------------------------------------------------------------------------
# POST /api/v1/nodes/{id}/lxd/join
# ---------------------------------------------------------------------------


@nodes_bp.route("/<int:node_id>/lxd/join", methods=["POST"])
@auth_required
async def node_lxd_join(node_id: int) -> Any:
    """Join a node to an LXD cluster and record membership.

    Request body:
        cluster_id: LXD cluster ID (required)
        api_url:    node's LXD API URL (required)
        member_name: cluster member name (required)

    Reuses lxd_extra join orchestration and inserts an lxd_cluster_members row.
    """
    raw = await request.get_json(silent=True)
    if raw is None:
        return err_bad_request("JSON body required")

    cluster_id_raw = (raw.get("cluster_id") or "")
    api_url = (raw.get("api_url") or "").strip()
    member_name = (raw.get("member_name") or "").strip()

    if not cluster_id_raw:
        return err_bad_request("cluster_id is required")
    if not api_url:
        return err_bad_request("api_url is required")
    if not member_name:
        return err_bad_request("member_name is required")

    db = get_db()
    node = db(db.nodes.id == node_id).select().first() if hasattr(db, "nodes") else None
    if not node:
        return err_not_found(f"Node {node_id} not found")

    if not _is_cross_tenant():
        if _g(node, "tenant_id", "__default__") != _current_tenant_id():
            return err_not_found(f"Node {node_id} not found")

    from ..clients import lxd_extra

    try:
        token = lxd_extra.mint_join_token(
            cluster_id=str(cluster_id_raw), ttl_seconds=3600
        )
        lxd_extra.cluster_join(
            node_address=api_url,
            join_token=token.token,
            server_address=api_url,
            cluster_id=str(cluster_id_raw),
        )
    except lxd_extra.LXDError as exc:
        return envelope_error("lxd_join_failed", str(exc), 502)

    now = datetime.now(timezone.utc)

    try:
        if hasattr(db, "lxd_cluster_members"):
            db.lxd_cluster_members.insert(
                cluster_id=cluster_id_raw,
                member_name=member_name,
                api_url=api_url,
                status="joined",
                joined_at=now,
                created_at=now,
            )
        if _g(node, "state") != "ready":
            db(db.nodes.id == node_id).update(
                state="ready",
                updated_at=now,
            )
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.exception("DB error recording LXD membership for node %s: %s", node_id, exc)
        return err_internal(str(exc))

    log.info(
        "Node %s joined LXD cluster %s as member %s",
        node_id, cluster_id_raw, member_name,
    )
    return envelope_success(
        {
            "node_id": node_id,
            "cluster_id": cluster_id_raw,
            "joined_at": now.isoformat(),
        },
        status_code=201,
    )
