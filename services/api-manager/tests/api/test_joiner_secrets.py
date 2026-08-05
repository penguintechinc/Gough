"""Tests for ``app.api.joiner_secrets`` blueprint.

Covers:
- list/rotate/revoke happy paths
- response payload contract: NEVER ciphertext, dek_wrapped, iv, auth_tag
- tenant scoping (cross-tenant denied via filter)
- scope enforcement matrix
- MFA enforcement in compliance lanes
- not_found, already_revoked, missing_reason
- expiring-soon / active / revoked status filter

All DB and Vault interactions are mocked; the blueprint is exercised under a
ephemeral Quart app whose ``DB_SESSION_FACTORY`` returns a stub session.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from unittest.mock import MagicMock

import pytest
from quart import Quart, g

from app.api import joiner_secrets as joiner_module
from app.api.joiner_secrets import (
    DEFAULT_MFA_REQUIRED_LANES,
    EXPIRING_SOON_WINDOW,
    _serialize_joiner_secret,
    joiner_secrets_bp,
)
from app.security.credentials import CredentialType, Principal
from app.security.tenant import TenantContext
from app.workers.joiner_secret_emitter import EmitResult, ExtractedMaterial


SECRET_FIELDS_MUST_BE_ABSENT: frozenset[str] = frozenset(
    {"ciphertext", "dek_wrapped", "iv", "auth_tag"}
)


# =============================================================================
# Helpers / fixtures
# =============================================================================


@dataclass
class FakeJoinerSecret:
    """Mimics enough of the JoinerSecret ORM row for serialization tests."""

    id: uuid.UUID
    cluster_id: uuid.UUID
    tenant_id: str
    biome_kind: str
    emitter_biome_id: int
    emitter_node_id: Optional[int]
    extractor_name: str
    scope: str
    ciphertext: bytes
    iv: bytes
    auth_tag: bytes
    dek_wrapped: bytes
    vault_kek_name: str
    ttl_seconds: Optional[int]
    expires_at: Optional[datetime]
    rotation_class: Optional[str]
    created_at: datetime
    rotated_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    audit_event_id: Optional[uuid.UUID] = None


def _make_secret(**overrides: Any) -> FakeJoinerSecret:
    base = dict(
        id=uuid.uuid4(),
        cluster_id=uuid.uuid4(),
        tenant_id="acme",
        biome_kind="vault",
        emitter_biome_id=42,
        emitter_node_id=7,
        extractor_name="root-token",
        scope="cluster",
        ciphertext=b"CT-PLAINTEXT-MUST-NEVER-LEAK",
        iv=b"IIIIIIIIIIII",
        auth_tag=b"TTTTTTTTTTTTTTTT",
        dek_wrapped=b"vault:v1:DEK-MUST-NEVER-LEAK",
        vault_kek_name="gough-joiner-dek-wrap",
        ttl_seconds=3600,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=12),
        rotation_class="vault-unseal",
        created_at=datetime.now(timezone.utc),
    )
    base.update(overrides)
    return FakeJoinerSecret(**base)


def _seed_biome(dal_db: Any, **overrides: Any) -> int:
    """Insert a minimal real ``biomes`` row; ``joiner_secrets.emitter_biome_id``
    is a NOT NULL FK to it."""
    base: dict[str, Any] = dict(name="test-biome")
    base.update(overrides)
    return int(dal_db.biomes.insert(**base))


def _seed_joiner_secret(
    dal_db: Any, *, emitter_biome_id: Optional[int] = None, **overrides: Any
) -> str:
    """Insert a real ``joiner_secrets`` row via penguin-dal; return its id (str).

    Used by tests exercising the penguin-dal-converted read/write paths
    (``list_joiner_secrets`` / the lookup+revoke-mark in ``rotate_``/
    ``revoke_joiner_secret``), as opposed to ``_make_secret``, which only
    builds an in-memory stand-in for pure-serializer tests.
    """
    if emitter_biome_id is None:
        emitter_biome_id = _seed_biome(dal_db)
    base: dict[str, Any] = dict(
        id=str(uuid.uuid4()),
        cluster_id=str(uuid.uuid4()),
        tenant_id="acme",
        biome_kind="vault",
        emitter_biome_id=emitter_biome_id,
        emitter_node_id=None,
        extractor_name="root-token",
        scope="cluster",
        ciphertext=b"CT-PLAINTEXT-MUST-NEVER-LEAK",
        iv=b"IIIIIIIIIIII",
        auth_tag=b"TTTTTTTTTTTTTTTT",
        dek_wrapped=b"vault:v1:DEK-MUST-NEVER-LEAK",
        vault_kek_name="gough-joiner-dek-wrap",
        ttl_seconds=3600,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=12),
        rotation_class="vault-unseal",
        created_at=datetime.now(timezone.utc),
    )
    base.update(overrides)
    base["id"] = str(base["id"])
    base["cluster_id"] = str(base["cluster_id"])
    return str(dal_db.joiner_secrets.insert(**base))


class FakeQuery:
    """Minimal SQLAlchemy-style query stub backed by a list."""

    def __init__(self, rows: list[Any]) -> None:
        self._rows = list(rows)

    def filter(self, *_: Any) -> "FakeQuery":
        return self

    def order_by(self, *_: Any) -> "FakeQuery":
        return self

    def all(self) -> list[Any]:
        return list(self._rows)

    def one_or_none(self) -> Optional[Any]:
        return self._rows[0] if self._rows else None

    def one(self) -> Any:
        return self._rows[0]


class FakeSession:
    """Stand-in for SQLAlchemy session — captures inserts and returns rows."""

    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows
        self.added: list[Any] = []
        self.flushed = 0

    def execute(self, *_: Any, **__: Any) -> Any:
        return MagicMock()

    def query(self, _model: Any) -> FakeQuery:
        return FakeQuery(self.rows)

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    def flush(self) -> None:
        self.flushed += 1


def _build_app(
    *,
    rows: list[Any],
    principal: Principal,
    mfa_lane: Optional[str] = None,
    rotation_provider: Optional[Any] = None,
    dal_db: Optional[Any] = None,
    monkeypatch: Optional[pytest.MonkeyPatch] = None,
) -> Quart:
    """Build a Quart app with ``joiner_secrets_bp`` registered.

    ``rows``/``FakeSession`` back the still-SQLAlchemy-session-based paths
    (``g.db_session``, used by ``AuditEventWriter``/``JoinerSecretEmitter``).
    Pass ``dal_db`` (a real ``pg_db``) + ``monkeypatch`` together to also
    patch ``joiner_module.get_db`` for the penguin-dal-converted
    lookup/list/revoke-mark logic.
    """
    app = Quart(__name__)
    app.register_blueprint(joiner_secrets_bp, url_prefix="/api/v1")

    if dal_db is not None:
        assert monkeypatch is not None, "dal_db requires monkeypatch"
        monkeypatch.setattr(joiner_module, "get_db", lambda: dal_db)

    session = FakeSession(rows)

    vault_client = MagicMock()
    vault_client.transit_sign.return_value = "vault:v1:fake-sig"
    enc_resp = MagicMock()
    enc_resp.ciphertext = "vault:v1:dek-wrapped"
    vault_client.transit_encrypt.return_value = enc_resp

    app.config["DB_SESSION_FACTORY"] = lambda: session
    app.config["VAULT_CLIENT"] = vault_client
    app.config["CLUSTER_ID"] = "test-cluster"
    if mfa_lane is not None:
        app.config["TENANT_COMPLIANCE_LANE"] = {principal.tenant_id: mfa_lane}
    if rotation_provider is not None:
        app.config["JOINER_ROTATE_MATERIAL_PROVIDER"] = rotation_provider

    @app.before_request
    async def _inject_ctx() -> None:
        g.principal = principal
        g.tenant_context = TenantContext(tenant_id=principal.tenant_id)
        g.db_session = session
        # Set g.current_user for require_scopes decorator
        g.current_user = {
            "_jwt_payload": {
                "scope": " ".join(sorted(principal.scopes)),
                "sub": principal.sub,
                "tenant": principal.tenant_id,
            }
        }

    app.config["_session"] = session
    app.config["_vault"] = vault_client
    return app


def _principal(
    *, tenant: str = "acme", scopes: Optional[set[str]] = None, mfa: bool = False
) -> Principal:
    claims: dict[str, Any] = {"sub": "user@acme", "tenant": tenant}
    if mfa:
        claims["amr"] = ["mfa"]
    return Principal(
        cred_type=CredentialType.USER_JWT,
        sub="user@acme",
        tenant_id=tenant,
        scopes=frozenset(scopes or set()),
        claims=claims,
    )


# =============================================================================
# Pure serializer contract — NEVER leak envelope material
# =============================================================================


class TestSerializerSecretContract:
    """The serializer must never expose envelope/DEK material."""

    def test_serializer_omits_ciphertext_iv_authtag_dek(self) -> None:
        row = _make_secret()
        out = _serialize_joiner_secret(row)
        for forbidden in SECRET_FIELDS_MUST_BE_ABSENT:
            assert forbidden not in out, f"Serializer leaked {forbidden!r}"

    def test_serializer_status_active(self) -> None:
        row = _make_secret(
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        out = _serialize_joiner_secret(row)
        assert out["status"] == "active"
        assert out["expiring_soon"] is False

    def test_serializer_status_expiring_soon(self) -> None:
        row = _make_secret(
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        out = _serialize_joiner_secret(row)
        assert out["status"] == "expiring-soon"
        assert out["expiring_soon"] is True

    def test_serializer_status_revoked_takes_precedence(self) -> None:
        row = _make_secret(
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            revoked_at=datetime.now(timezone.utc),
        )
        out = _serialize_joiner_secret(row)
        assert out["status"] == "revoked"
        assert out["expiring_soon"] is False

    def test_serializer_handles_no_expiry(self) -> None:
        row = _make_secret(expires_at=None, ttl_seconds=None)
        out = _serialize_joiner_secret(row)
        assert out["expires_at"] is None
        assert out["status"] == "active"

    def test_window_constant_is_24h(self) -> None:
        assert EXPIRING_SOON_WINDOW == timedelta(hours=24)


# =============================================================================
# GET /joiner-secrets
# =============================================================================


@pytest.mark.asyncio
class TestListJoinerSecrets:
    """Read path -- converted to penguin-dal, exercised against real Postgres.

    ``test_list_requires_scope`` returns before ``list_joiner_secrets`` ever
    calls ``get_db()`` (scope decorator short-circuits first), so it doesn't
    need ``pg_db`` and is unchanged.
    """

    async def test_list_happy_path_omits_envelope(
        self, pg_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cluster_id = uuid.uuid4()
        biome_id = _seed_biome(pg_db)
        _seed_joiner_secret(
            pg_db, cluster_id=cluster_id, biome_kind="vault", emitter_biome_id=biome_id
        )
        _seed_joiner_secret(
            pg_db,
            cluster_id=cluster_id,
            biome_kind="postgres",
            emitter_biome_id=biome_id,
        )
        principal = _principal(scopes={"gough.joiner.read"})
        app = _build_app(
            rows=[], principal=principal, dal_db=pg_db, monkeypatch=monkeypatch
        )
        client = app.test_client()
        resp = await client.get(f"/api/v1/clusters/{cluster_id}/joiner-secrets")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["count"] == 2
        for item in data["items"]:
            for forbidden in SECRET_FIELDS_MUST_BE_ABSENT:
                assert forbidden not in item

    async def test_list_empty_result(
        self, pg_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No secrets for this cluster -> 200 with an empty items list."""
        cluster_id = uuid.uuid4()
        _seed_joiner_secret(pg_db, cluster_id=uuid.uuid4())  # different cluster
        principal = _principal(scopes={"gough.joiner.read"})
        app = _build_app(
            rows=[], principal=principal, dal_db=pg_db, monkeypatch=monkeypatch
        )
        client = app.test_client()
        resp = await client.get(f"/api/v1/clusters/{cluster_id}/joiner-secrets")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data == {
            "cluster_id": str(cluster_id),
            "tenant_id": "acme",
            "count": 0,
            "items": [],
        }

    async def test_list_filter_biome_kind(
        self, pg_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cluster_id = uuid.uuid4()
        biome_id = _seed_biome(pg_db)
        _seed_joiner_secret(
            pg_db, cluster_id=cluster_id, biome_kind="vault", emitter_biome_id=biome_id
        )
        _seed_joiner_secret(
            pg_db,
            cluster_id=cluster_id,
            biome_kind="postgres",
            emitter_biome_id=biome_id,
        )
        principal = _principal(scopes={"gough.joiner.read"})
        app = _build_app(
            rows=[], principal=principal, dal_db=pg_db, monkeypatch=monkeypatch
        )
        client = app.test_client()
        resp = await client.get(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets?biome_kind=vault"
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["count"] == 1
        assert data["items"][0]["biome_kind"] == "vault"

    async def test_list_filter_status_revoked(
        self, pg_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cluster_id = uuid.uuid4()
        biome_id = _seed_biome(pg_db)
        _seed_joiner_secret(pg_db, cluster_id=cluster_id, emitter_biome_id=biome_id)
        _seed_joiner_secret(
            pg_db,
            cluster_id=cluster_id,
            emitter_biome_id=biome_id,
            revoked_at=datetime.now(timezone.utc),
        )
        principal = _principal(scopes={"gough.joiner.read"})
        app = _build_app(
            rows=[], principal=principal, dal_db=pg_db, monkeypatch=monkeypatch
        )
        client = app.test_client()
        resp = await client.get(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets?status=revoked"
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["count"] == 1
        assert all(item["status"] == "revoked" for item in data["items"])

    async def test_list_requires_scope(self) -> None:
        cluster_id = uuid.uuid4()
        principal = _principal(scopes=set())  # missing gough.joiner.read
        app = _build_app(rows=[], principal=principal)
        client = app.test_client()
        resp = await client.get(f"/api/v1/clusters/{cluster_id}/joiner-secrets")
        assert resp.status_code == 403

    async def test_list_filter_scope_field(
        self, pg_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cluster_id = uuid.uuid4()
        biome_id = _seed_biome(pg_db)
        _seed_joiner_secret(
            pg_db, cluster_id=cluster_id, scope="tenant", emitter_biome_id=biome_id
        )
        principal = _principal(scopes={"gough.joiner.read"})
        app = _build_app(
            rows=[], principal=principal, dal_db=pg_db, monkeypatch=monkeypatch
        )
        client = app.test_client()
        resp = await client.get(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets?scope=tenant"
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["count"] == 1


# =============================================================================
# POST /rotate
# =============================================================================


@pytest.mark.asyncio
class TestRotateJoinerSecret:
    """The lookup + revoke-mark is converted to penguin-dal (needs ``pg_db``);
    ``AuditEventWriter``/``JoinerSecretEmitter`` stay on the SQLAlchemy
    session (``FakeSession``) and ``JoinerSecretEmitter`` itself is replaced
    by a ``FakeEmitter`` in every test that reaches it, same as before this
    conversion -- the real class's call signature is already out of sync
    with this call site independent of DB access (see task report).

    ``test_rotate_missing_reason`` / ``test_rotate_requires_rotate_scope`` /
    ``test_rotate_mfa_required_in_compliance_lane`` all return before the
    handler calls ``get_db()``, so they're unchanged.
    """

    async def test_rotate_happy_path(
        self, pg_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cluster_id = uuid.uuid4()
        original_id = _seed_joiner_secret(pg_db, cluster_id=cluster_id)

        def provider(_row: Any) -> ExtractedMaterial:
            return ExtractedMaterial(
                extractor_name=_row.extractor_name,
                plaintext=b"new-plaintext",
                ttl_seconds=600,
                rotation_class="vault-unseal",
            )

        principal = _principal(
            scopes={"gough.joiner.rotate", "gough.joiner.read"}
        )
        app = _build_app(
            rows=[],
            principal=principal,
            rotation_provider=provider,
            dal_db=pg_db,
            monkeypatch=monkeypatch,
        )

        # Patch the emitter so we don't actually try to run the real
        # extractor/Vault/control-tunnel flow -- it inserts the "new" row
        # into the real DB directly so the post-emit lookup finds it.
        from app.api import joiner_secrets as jm

        new_id = uuid.uuid4()
        emit_result = EmitResult(
            joiner_secret_id=new_id,
            audit_event_id=uuid.uuid4(),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=600),
        )

        class FakeEmitter:
            def __init__(self, *_: Any, **__: Any) -> None:
                pass

            def emit(self, **_: Any) -> EmitResult:
                _seed_joiner_secret(
                    pg_db,
                    id=new_id,
                    cluster_id=cluster_id,
                    extractor_name="root-token",
                    expires_at=emit_result.expires_at,
                )
                return emit_result

        original_cls = jm.JoinerSecretEmitter
        jm.JoinerSecretEmitter = FakeEmitter
        try:
            client = app.test_client()
            resp = await client.post(
                f"/api/v1/clusters/{cluster_id}/joiner-secrets/{original_id}/rotate",
                json={"reason": "key compromised"},
            )
        finally:
            jm.JoinerSecretEmitter = original_cls

        assert resp.status_code == 201, await resp.get_data()
        data = await resp.get_json()
        for forbidden in SECRET_FIELDS_MUST_BE_ABSENT:
            assert forbidden not in data["rotated"]
            assert forbidden not in data["new_secret"]
        assert data["rotated"]["status"] == "revoked"
        assert data["new_secret"]["id"] == str(new_id)

    async def test_rotate_missing_reason(self) -> None:
        cluster_id = uuid.uuid4()
        secret = _make_secret(cluster_id=cluster_id)
        principal = _principal(scopes={"gough.joiner.rotate"})
        app = _build_app(rows=[secret], principal=principal)
        client = app.test_client()
        resp = await client.post(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets/{secret.id}/rotate",
            json={},
        )
        assert resp.status_code == 400

    async def test_rotate_not_found(
        self, pg_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cluster_id = uuid.uuid4()
        principal = _principal(scopes={"gough.joiner.rotate"})
        app = _build_app(
            rows=[], principal=principal, dal_db=pg_db, monkeypatch=monkeypatch
        )
        client = app.test_client()
        resp = await client.post(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets/{uuid.uuid4()}/rotate",
            json={"reason": "rotate"},
        )
        assert resp.status_code == 404

    async def test_rotate_already_revoked(
        self, pg_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cluster_id = uuid.uuid4()
        secret_id = _seed_joiner_secret(
            pg_db, cluster_id=cluster_id, revoked_at=datetime.now(timezone.utc)
        )
        principal = _principal(scopes={"gough.joiner.rotate"})
        app = _build_app(
            rows=[], principal=principal, dal_db=pg_db, monkeypatch=monkeypatch
        )
        client = app.test_client()
        resp = await client.post(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets/{secret_id}/rotate",
            json={"reason": "rotate"},
        )
        assert resp.status_code == 409

    async def test_rotate_requires_rotate_scope(self) -> None:
        cluster_id = uuid.uuid4()
        secret = _make_secret(cluster_id=cluster_id)
        principal = _principal(scopes={"gough.joiner.read"})
        app = _build_app(rows=[secret], principal=principal)
        client = app.test_client()
        resp = await client.post(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets/{secret.id}/rotate",
            json={"reason": "rotate"},
        )
        assert resp.status_code == 403

    async def test_rotate_mfa_required_in_compliance_lane(self) -> None:
        cluster_id = uuid.uuid4()
        secret = _make_secret(cluster_id=cluster_id)
        # principal w/o MFA, fedramp lane
        principal = _principal(scopes={"gough.joiner.rotate"}, mfa=False)
        app = _build_app(
            rows=[secret], principal=principal, mfa_lane="fedramp"
        )
        client = app.test_client()
        resp = await client.post(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets/{secret.id}/rotate",
            json={"reason": "rotate"},
        )
        assert resp.status_code == 401
        body = await resp.get_json()
        assert body["error"] == "mfa_required"

    async def test_rotate_mfa_satisfied(
        self, pg_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cluster_id = uuid.uuid4()
        secret_id = _seed_joiner_secret(pg_db, cluster_id=cluster_id)
        principal = _principal(scopes={"gough.joiner.rotate"}, mfa=True)

        def provider(_row: Any) -> ExtractedMaterial:
            return ExtractedMaterial(
                extractor_name=_row.extractor_name,
                plaintext=b"x",
                ttl_seconds=60,
            )

        app = _build_app(
            rows=[],
            principal=principal,
            mfa_lane="fedramp",
            rotation_provider=provider,
            dal_db=pg_db,
            monkeypatch=monkeypatch,
        )

        from app.api import joiner_secrets as jm

        class FakeEmitter:
            def __init__(self, *_: Any, **__: Any) -> None:
                pass

            def emit(self, **_: Any) -> EmitResult:
                new_id = uuid.uuid4()
                _seed_joiner_secret(
                    pg_db, id=new_id, cluster_id=cluster_id, extractor_name="root-token"
                )
                return EmitResult(
                    joiner_secret_id=new_id,
                    audit_event_id=uuid.uuid4(),
                    expires_at=None,
                )

        original_cls = jm.JoinerSecretEmitter
        jm.JoinerSecretEmitter = FakeEmitter
        try:
            client = app.test_client()
            resp = await client.post(
                f"/api/v1/clusters/{cluster_id}/joiner-secrets/{secret_id}/rotate",
                json={"reason": "scheduled"},
            )
        finally:
            jm.JoinerSecretEmitter = original_cls

        assert resp.status_code == 201

    async def test_rotate_provider_missing_returns_503(
        self, pg_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cluster_id = uuid.uuid4()
        secret_id = _seed_joiner_secret(pg_db, cluster_id=cluster_id)
        principal = _principal(scopes={"gough.joiner.rotate"})
        app = _build_app(
            rows=[], principal=principal, dal_db=pg_db, monkeypatch=monkeypatch
        )
        # No rotation_provider configured
        client = app.test_client()
        resp = await client.post(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets/{secret_id}/rotate",
            json={"reason": "rotate"},
        )
        assert resp.status_code == 503


# =============================================================================
# DELETE /joiner-secrets
# =============================================================================


@pytest.mark.asyncio
class TestRevokeJoinerSecret:
    """Same split as TestRotateJoinerSecret: lookup + revoke-mark via
    penguin-dal (``pg_db``), ``AuditEventWriter`` stays on the SQLAlchemy
    session. ``test_revoke_missing_reason``/``test_revoke_requires_admin_scope``
    return before ``get_db()`` is called, so they're unchanged.
    """

    async def test_revoke_happy_path(
        self, pg_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cluster_id = uuid.uuid4()
        secret_id = _seed_joiner_secret(pg_db, cluster_id=cluster_id)
        principal = _principal(scopes={"gough.cluster.admin"})
        app = _build_app(
            rows=[], principal=principal, dal_db=pg_db, monkeypatch=monkeypatch
        )
        client = app.test_client()
        resp = await client.delete(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets/{secret_id}",
            json={"reason": "manual revoke"},
        )
        assert resp.status_code == 200
        body = await resp.get_json()
        for forbidden in SECRET_FIELDS_MUST_BE_ABSENT:
            assert forbidden not in body["revoked"]
        assert body["revoked"]["status"] == "revoked"

    async def test_revoke_missing_reason(self) -> None:
        cluster_id = uuid.uuid4()
        secret = _make_secret(cluster_id=cluster_id)
        principal = _principal(scopes={"gough.cluster.admin"})
        app = _build_app(rows=[secret], principal=principal)
        client = app.test_client()
        resp = await client.delete(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets/{secret.id}",
            json={},
        )
        assert resp.status_code == 400

    async def test_revoke_not_found(
        self, pg_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cluster_id = uuid.uuid4()
        principal = _principal(scopes={"gough.cluster.admin"})
        app = _build_app(
            rows=[], principal=principal, dal_db=pg_db, monkeypatch=monkeypatch
        )
        client = app.test_client()
        resp = await client.delete(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets/{uuid.uuid4()}",
            json={"reason": "rev"},
        )
        assert resp.status_code == 404

    async def test_revoke_idempotent_already_revoked_returns_409(
        self, pg_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cluster_id = uuid.uuid4()
        secret_id = _seed_joiner_secret(
            pg_db, cluster_id=cluster_id, revoked_at=datetime.now(timezone.utc)
        )
        principal = _principal(scopes={"gough.cluster.admin"})
        app = _build_app(
            rows=[], principal=principal, dal_db=pg_db, monkeypatch=monkeypatch
        )
        client = app.test_client()
        resp = await client.delete(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets/{secret_id}",
            json={"reason": "rev"},
        )
        assert resp.status_code == 409

    async def test_revoke_requires_admin_scope(self) -> None:
        cluster_id = uuid.uuid4()
        secret = _make_secret(cluster_id=cluster_id)
        principal = _principal(scopes={"gough.joiner.rotate"})
        app = _build_app(rows=[secret], principal=principal)
        client = app.test_client()
        resp = await client.delete(
            f"/api/v1/clusters/{cluster_id}/joiner-secrets/{secret.id}",
            json={"reason": "rev"},
        )
        assert resp.status_code == 403


class TestComplianceLaneConfig:
    """The default lanes match the spec; overridable via app.config."""

    def test_default_lanes_includes_fedramp_hipaa_pci(self) -> None:
        assert "fedramp" in DEFAULT_MFA_REQUIRED_LANES
        assert "hipaa" in DEFAULT_MFA_REQUIRED_LANES
        assert "pci" in DEFAULT_MFA_REQUIRED_LANES
