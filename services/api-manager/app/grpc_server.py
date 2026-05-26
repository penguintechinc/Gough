"""gRPC servicer implementations for Plan 2 (Deployment).

Thin wrappers over the same service/dal functions used by the REST endpoints.
No business logic lives here — all logic is in the REST layer functions.

mTLS is Plan 4 scope; the runner uses an insecure channel until then.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import string
from datetime import datetime, timezone
from typing import Any

import grpc

# The protoc-generated *_pb2_grpc.py files use bare `from gough import …`.
# Adding app/grpc to sys.path makes the `gough` package importable by that name.
_GRPC_PKG_DIR = os.path.join(os.path.dirname(__file__), "grpc")
if _GRPC_PKG_DIR not in sys.path:
    sys.path.insert(0, _GRPC_PKG_DIR)

from gough import ipxe_pb2, ipxe_pb2_grpc  # noqa: E402
from gough import joiner_pb2, joiner_pb2_grpc  # noqa: E402
from gough import biomes_pb2, biomes_pb2_grpc  # noqa: E402
from gough import audit_pb2, audit_pb2_grpc  # noqa: E402
from gough import identity_pb2, identity_pb2_grpc  # noqa: E402

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# IPXE servicer
# ---------------------------------------------------------------------------


class IPXEServicer(ipxe_pb2_grpc.IPXEServicer):
    """gRPC handlers for IPXE service — delegates to ipxe.py helpers."""

    async def MintBootstrapToken(
        self,
        request: ipxe_pb2.MintBootstrapTokenRequest,
        context: grpc.aio.ServicerContext,
    ) -> ipxe_pb2.MintBootstrapTokenResponse:
        from app.api.ipxe import _find_node_or_machine_by_mac, _mint_bootstrap_jwt
        from app.models import get_db

        try:
            db = get_db()
            node = None
            if request.node_id:
                node = await asyncio.to_thread(
                    lambda: db(db.nodes.id == request.node_id).select().first()
                    if hasattr(db, "nodes") else None
                )
            if node is None:
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Node {request.node_id} not found")
                return ipxe_pb2.MintBootstrapTokenResponse()

            mac: str = getattr(node, "primary_nic_mac", None) or ""
            dmi_uuid: str = getattr(node, "dmi_uuid", None) or ""

            token, _nonce = await asyncio.to_thread(
                lambda: _mint_bootstrap_jwt(mac, phase="deploy", dmi_uuid_hint=dmi_uuid)
            )

            now_ts = int(datetime.now(timezone.utc).timestamp())
            from app.api.ipxe import _BOOTSTRAP_JWT_TTL_SECONDS
            expiration = now_ts + _BOOTSTRAP_JWT_TTL_SECONDS

            return ipxe_pb2.MintBootstrapTokenResponse(
                token=token,
                expiration=expiration,
            )
        except Exception as exc:
            log.exception("MintBootstrapToken gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return ipxe_pb2.MintBootstrapTokenResponse()

    async def ResolveBootScript(
        self,
        request: ipxe_pb2.ResolveBootScriptRequest,
        context: grpc.aio.ServicerContext,
    ) -> ipxe_pb2.ResolveBootScriptResponse:
        from app.api.ipxe import (
            _normalize_mac,
            _find_node_or_machine_by_mac,
            _render_helper_ipxe_script,
            _render_deploy_ipxe_script,
        )
        import os

        try:
            mac = request.mac_address or ""
            normalized = await asyncio.to_thread(_normalize_mac, mac)
            if not normalized:
                await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"Invalid MAC: {mac}")
                return ipxe_pb2.ResolveBootScriptResponse()

            record: dict[str, Any] | None = await asyncio.to_thread(
                _find_node_or_machine_by_mac, normalized
            )
            if record is None:
                await context.abort(grpc.StatusCode.NOT_FOUND, f"MAC not found: {normalized}")
                return ipxe_pb2.ResolveBootScriptResponse()

            primary_url = os.getenv("PRIMARY_BASE_URL", "https://localhost")

            from app.api.ipxe import _mint_bootstrap_jwt
            token, _nonce = await asyncio.to_thread(
                lambda: _mint_bootstrap_jwt(
                    normalized,
                    phase="deploy",
                    dmi_uuid_hint=record.get("dmi_uuid"),
                )
            )

            script = await asyncio.to_thread(
                _render_deploy_ipxe_script, normalized, token, primary_url
            )

            return ipxe_pb2.ResolveBootScriptResponse(boot_script=script)
        except Exception as exc:
            log.exception("ResolveBootScript gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return ipxe_pb2.ResolveBootScriptResponse()

    async def BindMac(
        self,
        request: ipxe_pb2.BindMacRequest,
        context: grpc.aio.ServicerContext,
    ) -> ipxe_pb2.BindMacResponse:
        from app.api.ipxe import _normalize_mac
        from app.models import get_db

        try:
            normalized = await asyncio.to_thread(_normalize_mac, request.mac_address or "")
            if not normalized:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    f"Invalid MAC: {request.mac_address}",
                )
                return ipxe_pb2.BindMacResponse()

            db = get_db()
            node_id = request.node_id

            def _do_bind() -> tuple[bool, str]:
                if not hasattr(db, "nodes"):
                    raise RuntimeError("nodes table not available")

                node = None
                if node_id:
                    node = db(db.nodes.id == node_id).select().first()
                    if not node:
                        raise KeyError(f"Node not found: {node_id}")

                if node:
                    db(db.nodes.id == node.id).update(
                        primary_nic_mac=normalized,
                        updated_at=datetime.now(timezone.utc),
                    )
                    db.commit()
                    return True, str(node.id)

                new_id = db.nodes.insert(
                    tenant_id="__default__",
                    name=f"node-{normalized.replace(':', '')}",
                    state="new",
                    primary_nic_mac=normalized,
                )
                db.commit()
                return True, str(new_id)

            bound, result_node_id = await asyncio.to_thread(_do_bind)
            return ipxe_pb2.BindMacResponse(bound=bound, node_id=result_node_id)

        except KeyError as exc:
            await context.abort(grpc.StatusCode.NOT_FOUND, str(exc))
            return ipxe_pb2.BindMacResponse()
        except Exception as exc:
            log.exception("BindMac gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return ipxe_pb2.BindMacResponse()

    async def FetchCloudInit(
        self,
        request: ipxe_pb2.FetchCloudInitRequest,
        context: grpc.aio.ServicerContext,
    ) -> ipxe_pb2.FetchCloudInitResponse:
        from app.models import get_db

        _VALID_BASELINES = {"native", "hybrid", "full-virtual"}

        try:
            baseline = (request.baseline or "native").lower()
            if baseline not in _VALID_BASELINES:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    f"Invalid baseline; must be one of: {', '.join(sorted(_VALID_BASELINES))}",
                )
                return ipxe_pb2.FetchCloudInitResponse()

            node_id = request.node_id

            def _fetch() -> tuple[str, str]:
                db = get_db()
                node = db.nodes(node_id) if hasattr(db, "nodes") else None
                if not node:
                    raise KeyError(f"Node {node_id} not found")

                template_row = None
                if hasattr(db, "cloud_init_templates"):
                    template_row = db(
                        db.cloud_init_templates.is_default == True  # noqa: E712
                    ).select().first()

                if template_row is None:
                    raise LookupError("No default cloud-init template configured")

                hostname = getattr(node, "name", None) or str(node_id)
                content = getattr(template_row, "template_content", None) or ""
                rendered = string.Template(content).safe_substitute(
                    node_id=str(node_id),
                    hostname=hostname,
                    baseline=baseline,
                )
                return rendered, "text/plain; charset=utf-8"

            user_data, content_type = await asyncio.to_thread(_fetch)
            return ipxe_pb2.FetchCloudInitResponse(
                user_data=user_data,
                content_type=content_type,
            )

        except KeyError as exc:
            await context.abort(grpc.StatusCode.NOT_FOUND, str(exc))
            return ipxe_pb2.FetchCloudInitResponse()
        except LookupError as exc:
            await context.abort(grpc.StatusCode.NOT_FOUND, str(exc))
            return ipxe_pb2.FetchCloudInitResponse()
        except Exception as exc:
            log.exception("FetchCloudInit gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return ipxe_pb2.FetchCloudInitResponse()


# ---------------------------------------------------------------------------
# JoinerSecrets servicer
# ---------------------------------------------------------------------------


class JoinerSecretsServicer(joiner_pb2_grpc.JoinerSecretsServicer):
    """gRPC handlers for JoinerSecrets service — delegates to joiner_secrets.py helpers."""

    async def Emit(
        self,
        request: joiner_pb2.EmitRequest,
        context: grpc.aio.ServicerContext,
    ) -> joiner_pb2.EmitResponse:
        from app.api.joiner_secrets import _get_db_session
        from app.workers.joiner_secret_emitter import JoinerSecretEmitter, ExtractedMaterial
        from app.security.audit_chain import AuditEventWriter
        from quart import current_app
        import uuid as _uuid

        try:
            db = _get_db_session()
            vault_client = current_app.config.get("VAULT_CLIENT")
            audit_writer = AuditEventWriter(db_session=db, cluster_id="grpc", signer=None)
            emitter = JoinerSecretEmitter(
                db_session=db,
                vault_client=vault_client,
                audit_writer=audit_writer,
            )

            material_provider = current_app.config.get("JOINER_ROTATE_MATERIAL_PROVIDER")
            if material_provider is None:
                await context.abort(
                    grpc.StatusCode.UNAVAILABLE, "JOINER_ROTATE_MATERIAL_PROVIDER not configured"
                )
                return joiner_pb2.EmitResponse()

            cluster_id = _uuid.UUID(current_app.config.get("CLUSTER_ID", str(_uuid.uuid4())))
            tenant_id = "__default__"

            material: ExtractedMaterial = await asyncio.to_thread(
                material_provider, None
            )

            result = await asyncio.to_thread(
                emitter.emit,
                cluster_id=cluster_id,
                tenant_id=tenant_id,
                biome_kind=request.rotation_class,
                emitter_biome_id=None,
                emitter_node_id=request.node_id,
                scope=f"key_version:{request.key_version}",
                material=material,
                actor_sub="grpc",
                actor_scope=[],
                request_id=None,
            )

            from app.models_m1 import JoinerSecret
            row = db.query(JoinerSecret).filter(
                JoinerSecret.id == result.joiner_secret_id
            ).one()

            expires_at_str = row.expires_at.isoformat() if row.expires_at else ""
            return joiner_pb2.EmitResponse(
                secret_id=str(row.id),
                expires_at=expires_at_str,
            )

        except Exception as exc:
            log.exception("JoinerSecrets.Emit gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return joiner_pb2.EmitResponse()

    async def Consume(
        self,
        request: joiner_pb2.ConsumeRequest,
        context: grpc.aio.ServicerContext,
    ) -> joiner_pb2.ConsumeResponse:
        from app.api.joiner_secrets import _get_db_session
        from app.models_m1 import JoinerSecret
        import uuid as _uuid

        try:
            db = _get_db_session()

            def _fetch() -> JoinerSecret:
                row = (
                    db.query(JoinerSecret)
                    .filter(JoinerSecret.id == _uuid.UUID(request.secret_id))
                    .one_or_none()
                )
                if row is None:
                    raise KeyError(f"Secret not found: {request.secret_id}")
                if row.revoked_at is not None:
                    raise PermissionError(f"Secret {request.secret_id} is revoked")
                return row

            row = await asyncio.to_thread(_fetch)

            ciphertext: bytes = row.ciphertext or b""
            rotation_class: str = row.rotation_class or ""

            return joiner_pb2.ConsumeResponse(
                decrypted_secret=ciphertext,
                rotation_class=rotation_class,
            )

        except KeyError as exc:
            await context.abort(grpc.StatusCode.NOT_FOUND, str(exc))
            return joiner_pb2.ConsumeResponse()
        except PermissionError as exc:
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, str(exc))
            return joiner_pb2.ConsumeResponse()
        except Exception as exc:
            log.exception("JoinerSecrets.Consume gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return joiner_pb2.ConsumeResponse()

    async def Rotate(
        self,
        request: joiner_pb2.RotateRequest,
        context: grpc.aio.ServicerContext,
    ) -> joiner_pb2.RotateResponse:
        from app.api.joiner_secrets import _get_db_session
        from app.models_m1 import JoinerSecret
        from app.workers.joiner_secret_emitter import JoinerSecretEmitter
        from app.security.audit_chain import AuditEventWriter
        from quart import current_app
        import uuid as _uuid

        try:
            db = _get_db_session()

            row: JoinerSecret | None = (
                db.query(JoinerSecret)
                .filter(JoinerSecret.id == _uuid.UUID(request.secret_id))
                .one_or_none()
            )
            if row is None:
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Secret not found: {request.secret_id}")
                return joiner_pb2.RotateResponse()
            if row.revoked_at is not None:
                await context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Cannot rotate a revoked secret")
                return joiner_pb2.RotateResponse()

            material_provider = current_app.config.get("JOINER_ROTATE_MATERIAL_PROVIDER")
            if material_provider is None:
                await context.abort(
                    grpc.StatusCode.UNAVAILABLE, "JOINER_ROTATE_MATERIAL_PROVIDER not configured"
                )
                return joiner_pb2.RotateResponse()

            material = await asyncio.to_thread(material_provider, row)

            now = datetime.now(timezone.utc)
            row.revoked_at = now
            row.rotated_at = now
            db.flush()

            vault_client = current_app.config.get("VAULT_CLIENT")
            cluster_id = _uuid.UUID(current_app.config.get("CLUSTER_ID", str(_uuid.uuid4())))
            audit_writer = AuditEventWriter(db_session=db, cluster_id=str(cluster_id), signer=None)
            emitter = JoinerSecretEmitter(
                db_session=db,
                vault_client=vault_client,
                audit_writer=audit_writer,
            )

            result = await asyncio.to_thread(
                emitter.emit,
                cluster_id=cluster_id,
                tenant_id=row.tenant_id,
                biome_kind=row.biome_kind,
                emitter_biome_id=row.emitter_biome_id,
                emitter_node_id=row.emitter_node_id,
                scope=row.scope,
                material=material,
                actor_sub="grpc",
                actor_scope=[],
                request_id=None,
            )

            new_row = (
                db.query(JoinerSecret)
                .filter(JoinerSecret.id == result.joiner_secret_id)
                .one()
            )

            expires_at_str = new_row.expires_at.isoformat() if new_row.expires_at else ""
            return joiner_pb2.RotateResponse(
                new_secret_id=str(new_row.id),
                expires_at=expires_at_str,
            )

        except Exception as exc:
            log.exception("JoinerSecrets.Rotate gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return joiner_pb2.RotateResponse()

    async def Revoke(
        self,
        request: joiner_pb2.RevokeRequest,
        context: grpc.aio.ServicerContext,
    ) -> joiner_pb2.RevokeResponse:
        from app.api.joiner_secrets import _get_db_session
        from app.models_m1 import JoinerSecret
        import uuid as _uuid

        try:
            db = _get_db_session()

            def _do_revoke() -> bool:
                row = (
                    db.query(JoinerSecret)
                    .filter(JoinerSecret.id == _uuid.UUID(request.secret_id))
                    .one_or_none()
                )
                if row is None:
                    raise KeyError(f"Secret not found: {request.secret_id}")
                if row.revoked_at is not None:
                    return False
                row.revoked_at = datetime.now(timezone.utc)
                db.flush()
                return True

            revoked = await asyncio.to_thread(_do_revoke)
            return joiner_pb2.RevokeResponse(revoked=revoked)

        except KeyError as exc:
            await context.abort(grpc.StatusCode.NOT_FOUND, str(exc))
            return joiner_pb2.RevokeResponse()
        except Exception as exc:
            log.exception("JoinerSecrets.Revoke gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return joiner_pb2.RevokeResponse()

    async def List(
        self,
        request: joiner_pb2.JoinerListRequest,
        context: grpc.aio.ServicerContext,
    ) -> joiner_pb2.JoinerListResponse:
        from app.api.joiner_secrets import _get_db_session
        from app.models_m1 import JoinerSecret
        import uuid as _uuid
        import base64
        import json

        try:
            db = _get_db_session()
            limit = request.limit if request.limit > 0 else 50
            cursor = request.cursor or None

            def _fetch() -> tuple[list[JoinerSecret], str]:
                query = db.query(JoinerSecret).filter(
                    JoinerSecret.emitter_node_id == request.node_id
                )

                if cursor:
                    try:
                        decoded = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
                        after_id = _uuid.UUID(decoded["id"])
                        query = query.filter(JoinerSecret.id > after_id)
                    except Exception:
                        pass

                rows = query.order_by(JoinerSecret.created_at.desc()).limit(limit + 1).all()

                next_cur = ""
                if len(rows) > limit:
                    rows = rows[:limit]
                    last = rows[-1]
                    next_cur = base64.urlsafe_b64encode(
                        json.dumps({"id": str(last.id)}).encode()
                    ).decode()

                return rows, next_cur

            rows, next_cursor = await asyncio.to_thread(_fetch)

            secrets = [
                joiner_pb2.JoinerSecret(
                    id=str(r.id),
                    node_id=r.emitter_node_id or "",
                    rotation_class=r.rotation_class or "",
                    key_version=0,
                    created_at=r.created_at.isoformat() if r.created_at else "",
                    expires_at=r.expires_at.isoformat() if r.expires_at else "",
                )
                for r in rows
            ]

            return joiner_pb2.JoinerListResponse(
                secrets=secrets,
                next_cursor=next_cursor,
            )

        except Exception as exc:
            log.exception("JoinerSecrets.List gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return joiner_pb2.JoinerListResponse()


# ---------------------------------------------------------------------------
# Biomes servicer
# ---------------------------------------------------------------------------


class BiomesServicer(biomes_pb2_grpc.BiomesServicer):
    """gRPC handlers for Biomes service — delegates to biomes.py helpers."""

    async def DeployBiome(
        self,
        request: biomes_pb2.DeployBiomeRequest,
        context: grpc.aio.ServicerContext,
    ) -> biomes_pb2.DeployBiomeResponse:
        from app.models import get_db

        try:
            def _do_deploy() -> tuple[int, str]:
                db = get_db()

                # Validate biome exists
                if not hasattr(db, "biomes"):
                    raise RuntimeError("biomes table not available")

                biome = db(db.biomes.id == request.biome_id).select().first()
                if not biome:
                    raise KeyError(f"Biome not found: {request.biome_id}")

                # Validate node exists
                if not hasattr(db, "nodes"):
                    raise RuntimeError("nodes table not available")

                node = db(db.nodes.id == request.node_id).select().first()
                if not node:
                    raise KeyError(f"Node not found: {request.node_id}")

                # Create node_biome_assignments row
                if not hasattr(db, "node_biome_assignments"):
                    raise RuntimeError("node_biome_assignments table not available")

                assignment_id = db.node_biome_assignments.insert(
                    biome_id=request.biome_id,
                    node_id=request.node_id,
                    config=request.config,
                    state="pending",
                    created_at=datetime.now(timezone.utc),
                )
                db.commit()
                return assignment_id, "pending"

            assignment_id, status = await asyncio.to_thread(_do_deploy)
            return biomes_pb2.DeployBiomeResponse(
                deployment_id=str(assignment_id),
                status=status,
            )

        except KeyError as exc:
            await context.abort(grpc.StatusCode.NOT_FOUND, str(exc))
            return biomes_pb2.DeployBiomeResponse()
        except Exception as exc:
            log.exception("Biomes.DeployBiome gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return biomes_pb2.DeployBiomeResponse()

    async def GetBiome(
        self,
        request: biomes_pb2.BiomeGetRequest,
        context: grpc.aio.ServicerContext,
    ) -> biomes_pb2.BiomeGetResponse:
        from app.models import get_db

        try:
            def _fetch() -> dict[str, Any]:
                db = get_db()

                if not hasattr(db, "biomes"):
                    raise RuntimeError("biomes table not available")

                biome = db(db.biomes.id == request.biome_id).select().first()
                if not biome:
                    raise KeyError(f"Biome not found: {request.biome_id}")

                return {
                    "id": biome.id,
                    "name": getattr(biome, "name", ""),
                    "version": getattr(biome, "version", ""),
                    "state": getattr(biome, "state", ""),
                    "created_at": int(getattr(biome, "created_at", datetime.now(timezone.utc)).timestamp()),
                }

            biome_data = await asyncio.to_thread(_fetch)
            biome_proto = biomes_pb2.Biome(
                id=biome_data["id"],
                name=biome_data["name"],
                version=biome_data["version"],
                state=biome_data["state"],
                created_at=biome_data["created_at"],
            )
            return biomes_pb2.BiomeGetResponse(biome=biome_proto)

        except KeyError as exc:
            await context.abort(grpc.StatusCode.NOT_FOUND, str(exc))
            return biomes_pb2.BiomeGetResponse()
        except Exception as exc:
            log.exception("Biomes.GetBiome gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return biomes_pb2.BiomeGetResponse()

    async def VerifySignature(
        self,
        request: biomes_pb2.VerifySignatureRequest,
        context: grpc.aio.ServicerContext,
    ) -> biomes_pb2.VerifySignatureResponse:
        from app.models import get_db

        try:
            def _verify() -> tuple[bool, str]:
                db = get_db()

                if not hasattr(db, "biomes"):
                    raise RuntimeError("biomes table not available")

                biome = db(db.biomes.id == request.biome_id).select().first()
                if not biome:
                    raise KeyError(f"Biome not found: {request.biome_id}")

                verified = getattr(biome, "signature_verified", False)
                reason = "Signature verified" if verified else "Signature not verified"
                return verified, reason

            verified, reason = await asyncio.to_thread(_verify)
            return biomes_pb2.VerifySignatureResponse(
                verified=verified,
                reason=reason,
            )

        except KeyError as exc:
            await context.abort(grpc.StatusCode.NOT_FOUND, str(exc))
            return biomes_pb2.VerifySignatureResponse()
        except Exception as exc:
            log.exception("Biomes.VerifySignature gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return biomes_pb2.VerifySignatureResponse()


# ---------------------------------------------------------------------------
# Audit servicer
# ---------------------------------------------------------------------------


class AuditServicer(audit_pb2_grpc.AuditServicer):
    """gRPC Audit service — wraps AuditEventWriter for chain-append + verify/export."""

    async def AppendEvent(
        self,
        request: audit_pb2.AppendEventRequest,
        context: grpc.aio.ServicerContext,
    ) -> audit_pb2.AppendEventResponse:
        from app.security.audit_chain import AuditEventWriter
        from app.models_m1 import AuditEvent as AuditEventModel
        from quart import current_app
        import json
        import uuid as _uuid

        try:
            event_data = json.loads(request.event_data)

            db = current_app.db_session
            cluster_id = event_data.get("cluster_id", "grpc")

            def _do_append() -> AuditEventModel:
                writer = AuditEventWriter(db_session=db, cluster_id=cluster_id, signer=None)
                event = writer.append(
                    actor_sub=event_data.get("actor_sub", "unknown"),
                    action=event_data.get("action", "unknown"),
                    resource_kind=event_data.get("resource_kind", "unknown"),
                    resource_id=event_data.get("resource_id"),
                    tenant_id=event_data.get("tenant_id"),
                    actor_scope=event_data.get("actor_scope"),
                    before=event_data.get("before_json"),
                    after=event_data.get("after_json"),
                    request_id=event_data.get("request_id"),
                    source_ip=event_data.get("source_ip"),
                    user_agent=event_data.get("user_agent"),
                )
                db.commit()
                return event

            event = await asyncio.to_thread(_do_append)
            return audit_pb2.AppendEventResponse(
                event_id=str(event.id),
                timestamp=int(event.ts.timestamp()),
            )

        except json.JSONDecodeError as exc:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "event_data must be JSON")
            return audit_pb2.AppendEventResponse()
        except Exception as exc:
            log.exception("Audit.AppendEvent gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return audit_pb2.AppendEventResponse()

    async def Stream(
        self,
        request: audit_pb2.StreamRequest,
        context: grpc.aio.ServicerContext,
    ):
        from quart import current_app
        from sqlalchemy import text
        import json

        try:
            db = current_app.db_session

            def _fetch_rows() -> list:
                query = text('''
                    SELECT id, event_payload, ts
                    FROM audit_events
                    WHERE ts >= to_timestamp(:offset)
                    ORDER BY ts ASC
                ''')
                start_offset = request.start_offset if request.start_offset > 0 else 0
                rows = db.execute(query, {"offset": start_offset}).fetchall()
                return rows

            rows = await asyncio.to_thread(_fetch_rows)

            for row in rows:
                event_id, payload, ts = row[0], row[1], row[2]

                if request.filter:
                    try:
                        filter_obj = json.loads(request.filter)
                        if payload and isinstance(payload, dict):
                            after_json = payload.get("after_json", {})
                            if not all(after_json.get(k) == v for k, v in filter_obj.items()):
                                continue
                    except (json.JSONDecodeError, TypeError):
                        pass

                yield audit_pb2.StreamResponse(
                    event_id=str(event_id),
                    event_payload=json.dumps(payload) if payload else "{}",
                    timestamp=int(ts.timestamp()),
                )

        except Exception as exc:
            log.exception("Audit.Stream gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))

    async def Verify(
        self,
        request: audit_pb2.VerifyRequest,
        context: grpc.aio.ServicerContext,
    ) -> audit_pb2.VerifyResponse:
        from app.security.audit_chain import verify_chain
        from quart import current_app
        import uuid as _uuid

        try:
            db = current_app.db_session

            def _do_verify() -> dict:
                result = verify_chain(db, since=None, to=None)
                return result

            result = await asyncio.to_thread(_do_verify)
            verified = result["breaks"] == 0
            msg = "ok" if verified else f"Chain breaks: {result['breaks']}"

            return audit_pb2.VerifyResponse(
                verified=verified,
                verification_result=msg,
            )

        except Exception as exc:
            log.exception("Audit.Verify gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return audit_pb2.VerifyResponse()

    async def ExportRange(
        self,
        request: audit_pb2.ExportRangeRequest,
        context: grpc.aio.ServicerContext,
    ) -> audit_pb2.ExportRangeResponse:
        from quart import current_app
        from sqlalchemy import text
        import json
        import uuid as _uuid

        try:
            db = current_app.db_session

            def _do_export() -> bytes:
                query = text('''
                    SELECT id, ts, cluster_id, tenant_id, actor_sub, actor_scope, action,
                           resource_kind, resource_id, before_json, after_json, request_id,
                           source_ip, user_agent, prev_hash, hash, signature
                    FROM audit_events
                    WHERE ts BETWEEN to_timestamp(:start) AND to_timestamp(:end)
                    ORDER BY ts ASC
                ''')
                rows = db.execute(
                    query,
                    {"start": request.start_time, "end": request.end_time},
                ).fetchall()

                lines = []
                for row in rows:
                    record = {
                        "id": str(row.id),
                        "ts": row.ts.isoformat(),
                        "cluster_id": row.cluster_id,
                        "tenant_id": row.tenant_id,
                        "actor_sub": row.actor_sub,
                        "actor_scope": row.actor_scope,
                        "action": row.action,
                        "resource_kind": row.resource_kind,
                        "resource_id": row.resource_id,
                        "before_json": row.before_json,
                        "after_json": row.after_json,
                        "request_id": row.request_id,
                        "source_ip": row.source_ip,
                        "user_agent": row.user_agent,
                    }
                    lines.append(json.dumps(record))

                return "\n".join(lines).encode("utf-8")

            export_data = await asyncio.to_thread(_do_export)
            export_id = str(_uuid.uuid4())

            return audit_pb2.ExportRangeResponse(
                export_data=export_data,
                export_id=export_id,
            )

        except Exception as exc:
            log.exception("Audit.ExportRange gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return audit_pb2.ExportRangeResponse()


# ---------------------------------------------------------------------------
# Identity servicer
# ---------------------------------------------------------------------------


class IdentityServicer(identity_pb2_grpc.IdentityServicer):
    """gRPC Identity service — SVID issuance and OTPN verification."""

    async def IssueSVID(
        self,
        request: identity_pb2.IssueSVIDRequest,
        context: grpc.aio.ServicerContext,
    ) -> identity_pb2.IssueSVIDResponse:
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtensionOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from datetime import datetime, timezone, timedelta
        import base64

        try:
            service_name = request.service_name or "gough-service"
            ttl_seconds = request.ttl_seconds if request.ttl_seconds > 0 else 3600

            def _issue_svid() -> tuple[str, str, int, str]:
                ca_cert_pem = os.getenv("GOUGH_CA_CERT_PEM")
                ca_key_pem = os.getenv("GOUGH_CA_KEY_PEM")

                if request.csr_pem:
                    csr = x509.load_pem_x509_csr(
                        request.csr_pem.encode(), backend=None
                    )
                    public_key = csr.public_key()
                else:
                    private_key = ec.generate_private_key(ec.SECP256R1())
                    public_key = private_key.public_key()

                if not ca_cert_pem or not ca_key_pem:
                    ca_private_key = ec.generate_private_key(ec.SECP256R1())
                    ca_public_key = ca_private_key.public_key()
                else:
                    ca_private_key = serialization.load_pem_private_key(
                        ca_key_pem.encode(), password=None, backend=None
                    )
                    ca_public_key = serialization.load_pem_public_key(
                        ca_cert_pem.encode(), backend=None
                    )

                now = datetime.now(timezone.utc)
                expires_at = now + timedelta(seconds=ttl_seconds)

                subject_name = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, service_name)
                ])
                issuer_name = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, "gough-ca")
                ])

                cert = x509.CertificateBuilder().subject_name(
                    subject_name
                ).issuer_name(
                    issuer_name
                ).public_key(
                    public_key
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    now
                ).not_valid_after(
                    expires_at
                ).add_extension(
                    x509.SubjectAlternativeName([
                        x509.UniformResourceIdentifier(
                            f"spiffe://penguintech.io/gough/{service_name}"
                        )
                    ]),
                    critical=False,
                ).sign(ca_private_key, hashes.SHA256())

                cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

                if request.csr_pem:
                    key_pem = ""
                else:
                    key_pem = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    ).decode()

                spiffe_id = f"spiffe://penguintech.io/gough/{service_name}"
                expires_ts = int(expires_at.timestamp())

                return cert_pem, key_pem, expires_ts, spiffe_id

            cert_pem, key_pem, expires_ts, spiffe_id = await asyncio.to_thread(_issue_svid)

            return identity_pb2.IssueSVIDResponse(
                certificate_pem=cert_pem,
                private_key_pem=key_pem,
                expires_at=expires_ts,
                spiffe_id=spiffe_id,
            )

        except Exception as exc:
            log.exception("Identity.IssueSVID gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return identity_pb2.IssueSVIDResponse()

    async def VerifyOTPN(
        self,
        request: identity_pb2.VerifyOTPNRequest,
        context: grpc.aio.ServicerContext,
    ) -> identity_pb2.VerifyOTPNResponse:
        from app.models_m1 import JoinerSecret
        from app.security.joiner_envelope import EnvelopeCiphertext, decrypt_envelope
        from quart import current_app
        import uuid as _uuid

        try:
            db = current_app.db_session
            vault_client = current_app.config.get("VAULT_CLIENT")

            def _verify_otp() -> tuple[bool, bytes, str, str]:
                row = (
                    db.query(JoinerSecret)
                    .filter(
                        JoinerSecret.emitter_node_id == request.node_id,
                        JoinerSecret.rotation_class == request.rotation_class,
                    )
                    .one_or_none()
                )

                if not row:
                    return False, b"", "", ""

                if row.revoked_at is not None:
                    return False, b"", "", ""

                envelope = EnvelopeCiphertext(
                    ciphertext=row.ciphertext,
                    iv=row.iv,
                    auth_tag=row.auth_tag,
                    dek_wrapped=row.dek_wrapped,
                    vault_kek_name=row.vault_kek_name,
                )

                try:
                    plaintext = decrypt_envelope(envelope, vault_client, joiner_secret_id=row.id)
                except Exception as e:
                    log.exception("Failed to decrypt envelope: %s", e)
                    return False, b"", "", ""

                return True, plaintext, row.rotation_class or "", str(request.node_id)

            valid, secret_bytes, rotation_class, node_id = await asyncio.to_thread(_verify_otp)

            return identity_pb2.VerifyOTPNResponse(
                valid=valid,
                decrypted_secret=secret_bytes,
                rotation_class=rotation_class,
                node_id=node_id,
            )

        except Exception as exc:
            log.exception("Identity.VerifyOTPN gRPC handler failed: %s", exc)
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return identity_pb2.VerifyOTPNResponse()
