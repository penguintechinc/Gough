"""Real-Postgres tests for ``app.grpc_server`` (JoinerSecretsServicer,
AuditServicer, IdentityServicer.VerifyOTPN).

Covers the penguin-dal conversion of these servicers: filter + empty-result
cases for reads, the atomic revoke+persist transaction for ``Rotate``, and a
dedicated RLS proof that ``_cross_tenant_scope()`` -- not an app-level filter
-- is what makes these gRPC methods see rows at all under Row Level
Security (see ``app.grpc_server._cross_tenant_scope`` docstring).

``app.grpc_server`` imports ``gough.identity_pb2`` at module level (for
``IdentityServicer``); that generated file's embedded ``FileDescriptorProto``
is corrupted -- ``FileDescriptorProto().ParseFromString()`` raises "Wire
format was corrupt" even standalone, independent of any protobuf/grpcio
version skew (confirmed) -- and there is no ``.proto`` source anywhere in
this repo to regenerate it from cleanly. This is a genuine, pre-existing,
already-in-production bug: ``app/__init__.py``'s ``_start_grpc`` wraps the
whole ``grpc_runner`` import in a bare ``try/except`` + ``logger.warning``,
so the ENTIRE gRPC server -- every servicer, not just Identity -- silently
fails to start in every deployed environment; the HTTP/REST app boots fine
and masks it completely. Fixing the generated proto file is build-tooling,
out of scope for this task (not ``grpc_server.py``, ``joiner_secret_emitter
.py``, or a test file). ``_ensure_identity_pb2_importable()`` below installs
a minimal stand-in for ``gough.identity_pb2``/``gough.identity_pb2_grpc``
ONLY if the real import still fails, so ``app.grpc_server`` (and therefore
every servicer defined in it) can be imported and tested despite the
corrupted file -- and so this shim becomes an inert no-op automatically the
day someone fixes the real generated file.
"""

from __future__ import annotations

import json
import os
import sys
import types
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import Mock

import pytest
from quart import Quart


def _ensure_identity_pb2_importable() -> None:
    """Install a minimal ``gough.identity_pb2``/``identity_pb2_grpc`` stand-in.

    Only runs if the real generated modules still fail to import (see module
    docstring) -- becomes a no-op the moment that file is regenerated
    correctly. Never touches the real files on disk.
    """
    try:
        import gough.identity_pb2  # noqa: F401
        import gough.identity_pb2_grpc  # noqa: F401
        return
    except Exception:
        pass

    _grpc_pkg_dir = os.path.join(
        os.path.dirname(__file__), "..", "app", "grpc"
    )
    _grpc_pkg_dir = os.path.abspath(_grpc_pkg_dir)
    if _grpc_pkg_dir not in sys.path:
        sys.path.insert(0, _grpc_pkg_dir)

    import gough  # the real `app/grpc/gough` package -- ipxe_pb2 etc. parse fine

    class _Msg:
        """Minimal stand-in for a generated protobuf message class.

        Supports only keyword-constructed attribute access, matching how
        ``app.grpc_server`` and this test file use these two message types
        -- never real wire serialization (nothing here sends an Identity
        message over an actual socket).
        """

        def __init__(self, **kwargs: Any) -> None:
            for key, value in kwargs.items():
                setattr(self, key, value)

    pb2 = types.ModuleType("gough.identity_pb2")
    for name in (
        "IssueSVIDRequest",
        "IssueSVIDResponse",
        "VerifyOTPNRequest",
        "VerifyOTPNResponse",
    ):
        setattr(pb2, name, type(name, (_Msg,), {}))

    pb2_grpc = types.ModuleType("gough.identity_pb2_grpc")

    class IdentityServicer:
        """Minimal stand-in base class (the real one is an ``object`` subclass)."""

    pb2_grpc.IdentityServicer = IdentityServicer  # type: ignore[attr-defined]

    sys.modules["gough.identity_pb2"] = pb2
    sys.modules["gough.identity_pb2_grpc"] = pb2_grpc
    gough.identity_pb2 = pb2  # type: ignore[attr-defined]
    gough.identity_pb2_grpc = pb2_grpc  # type: ignore[attr-defined]


_ensure_identity_pb2_importable()

from app.grpc_server import (  # noqa: E402
    AuditServicer,
    IdentityServicer,
    JoinerSecretsServicer,
)
from app.security.joiner_envelope import EnvelopeCiphertext, encrypt_envelope  # noqa: E402

pytestmark = pytest.mark.asyncio


# =============================================================================
# Fake gRPC context
# =============================================================================


class _AbortCalled(Exception):
    """Raised by ``FakeGrpcContext.abort`` -- mirrors real ``grpc.aio``
    semantics (``ServicerContext.abort`` always raises to terminate the
    RPC; see its docstring: "Raises: Exception: An exception is always
    raised"). Tests assert on ``context.aborted`` after catching this (or
    letting it propagate, matching what a real caller would see)."""

    def __init__(self, code: Any, details: str) -> None:
        self.code = code
        self.details = details
        super().__init__(f"{code}: {details}")


class FakeGrpcContext:
    """Minimal stand-in for ``grpc.aio.ServicerContext``."""

    def __init__(self) -> None:
        self.aborted: tuple[Any, str] | None = None

    async def abort(self, code: Any, details: str = "") -> None:
        self.aborted = (code, details)
        raise _AbortCalled(code, details)


# =============================================================================
# App-context helper
# =============================================================================


def _make_app(
    *,
    db: Any,
    vault_client: Any = None,
    material_provider: Any = None,
    cluster_id: str | None = None,
) -> Quart:
    """Build a bare Quart app exposing ``app.config["db"]`` for ``get_db()``.

    gRPC servicers run outside Quart's HTTP request pipeline (no
    ``before_request``/tenant middleware -- see
    ``app.grpc_server._cross_tenant_scope``); all they need from Quart is an
    active app context so ``app.models.get_db()``/``current_app.config``
    resolve, which is exactly what production gets too (see
    ``app/__init__.py``'s ``_start_grpc`` -- the gRPC server runs as an
    ``asyncio.ensure_future()`` task spawned from inside a
    ``before_serving`` hook's app context; new asyncio Tasks copy the
    current ``contextvars`` context at creation, so that single app context
    stays valid for every subsequent gRPC call for the life of the
    process).
    """
    app = Quart(__name__)
    app.config["db"] = db
    # CLUSTER_ID must be a valid UUID string -- app.grpc_server.JoinerSecretsServicer
    # .Emit/.Rotate parse it via uuid.UUID(...) (pre-existing, unchanged by this
    # conversion). Default to a fresh UUID rather than a human-readable label.
    app.config["CLUSTER_ID"] = cluster_id or str(uuid.uuid4())
    if vault_client is not None:
        app.config["VAULT_CLIENT"] = vault_client
    if material_provider is not None:
        app.config["JOINER_ROTATE_MATERIAL_PROVIDER"] = material_provider
    return app


@pytest.fixture
def mock_vault_client() -> Any:
    """Same round-trip mock as ``tests/workers/test_joiner_secret_emitter.py``."""
    client = Mock()
    client._wrapped_keys: dict[str, bytes] = {}

    def mock_encrypt(key_name: str, plaintext: bytes) -> Any:
        from app.clients.vault import VaultTransitEncryptResponse

        wrapped = f"vault:v1:{uuid.uuid4().hex}"
        client._wrapped_keys[wrapped] = plaintext
        return VaultTransitEncryptResponse(ciphertext=wrapped, key_version=1)

    def mock_decrypt(key_name: str, ciphertext: str) -> Any:
        from app.clients.vault import VaultTransitDecryptResponse

        if ciphertext not in client._wrapped_keys:
            raise ValueError(f"Unknown wrapped key: {ciphertext}")
        return VaultTransitDecryptResponse(plaintext=client._wrapped_keys[ciphertext])

    client.transit_encrypt = mock_encrypt
    client.transit_decrypt = mock_decrypt
    return client


# =============================================================================
# Seed helpers (real penguin-dal inserts -- pg_db is the owner role, RLS-exempt)
# =============================================================================


def _seed_node(dal_db: Any, **overrides: Any) -> int:
    """created_at/updated_at have no server-side DEFAULT (ORM-side
    ``default=`` only) -- supplied explicitly, matching every other
    direct-insert seed helper in this test suite (see
    ``tests/api/test_primary_dal_conversion.py``)."""
    now = datetime.now(timezone.utc)
    base: dict[str, Any] = dict(
        name=f"node-{uuid.uuid4().hex[:8]}",
        state="ready",
        tenant_id="acme",
        created_at=now,
        updated_at=now,
    )
    base.update(overrides)
    return int(dal_db.nodes.insert(**base))


def _seed_biome(dal_db: Any, **overrides: Any) -> int:
    base: dict[str, Any] = dict(name=f"biome-{uuid.uuid4().hex[:8]}", tenant_id="acme")
    base.update(overrides)
    return int(dal_db.biomes.insert(**base))


def _seed_assignment(dal_db: Any, *, node_id: int, egg_id: int, **overrides: Any) -> int:
    """``phase``/``assigned_at``/``created_at``/``updated_at`` are all NOT
    NULL with no (or Python-only) defaults -- supplied explicitly."""
    now = datetime.now(timezone.utc)
    base: dict[str, Any] = dict(
        node_id=node_id,
        egg_id=egg_id,
        tenant_id="acme",
        phase="post_deploy",
        status="ready",
        assigned_at=now,
        created_at=now,
        updated_at=now,
    )
    base.update(overrides)
    return int(dal_db.node_egg_assignments.insert(**base))


def _seed_joiner_secret(
    dal_db: Any,
    *,
    vault_client: Any,
    plaintext: bytes = b"secret-plaintext",
    emitter_biome_id: int | None = None,
    **overrides: Any,
) -> tuple[str, bytes]:
    """Insert a real, genuinely-decryptable ``joiner_secrets`` row.

    Returns ``(id, plaintext)`` so callers can assert Consume/VerifyOTPN
    return the exact bytes that went in -- proving real decryption, not
    just "a response came back".
    """
    if emitter_biome_id is None:
        emitter_biome_id = _seed_biome(dal_db)
    envelope: EnvelopeCiphertext = encrypt_envelope(
        plaintext=plaintext, vault_client=vault_client, vault_kek_name="gough-joiner-dek-wrap"
    )
    base: dict[str, Any] = dict(
        id=str(uuid.uuid4()),
        cluster_id=str(uuid.uuid4()),
        tenant_id="acme",
        biome_kind="vault",
        emitter_biome_id=emitter_biome_id,
        emitter_node_id=None,
        extractor_name="root-token",
        scope="cluster",
        ciphertext=envelope.ciphertext,
        iv=envelope.iv,
        auth_tag=envelope.auth_tag,
        dek_wrapped=envelope.dek_wrapped,
        vault_kek_name=envelope.vault_kek_name,
        ttl_seconds=3600,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=12),
        rotation_class="vault-unseal",
        created_at=datetime.now(timezone.utc),
    )
    base.update(overrides)
    base["id"] = str(base["id"])
    base["cluster_id"] = str(base["cluster_id"])
    new_id = str(dal_db.joiner_secrets.insert(**base))
    return new_id, plaintext


def _seed_audit_event(dal_db: Any, **overrides: Any) -> str:
    """Matches ``tests/api/test_audit.py``'s helper of the same name."""
    base: dict[str, Any] = dict(
        id=str(uuid.uuid4()),
        ts=datetime.now(timezone.utc),
        cluster_id="test-cluster",
        tenant_id="acme",
        actor_sub="alice@acme",
        actor_scope=["gough.audit.read"],
        action="joiner.secret.emit",
        resource_kind="joiner_secret",
        resource_id=str(uuid.uuid4()),
        prev_hash=b"\x00" * 32,
        hash=b"\x11" * 32,
    )
    base.update(overrides)
    base["id"] = str(base["id"])
    return str(dal_db.audit_events.insert(**base))


# =============================================================================
# JoinerSecretsServicer.Emit
# =============================================================================


class TestEmit:
    async def test_emit_persists_secret_for_ready_node(
        self, pg_db: Any, mock_vault_client: Any
    ) -> None:
        node_id = _seed_node(pg_db)
        biome_id = _seed_biome(pg_db, biome_kind="k8s-primary", emits_joiner_secrets=True)
        _seed_assignment(pg_db, node_id=node_id, egg_id=biome_id, status="ready")

        material = Mock()
        material.extractor_name = "grpc-emit"
        material.plaintext = b"fresh-token"
        material.ttl_seconds = 3600
        material.rotation_class = "single_use"
        provider = Mock(return_value=material)

        app = _make_app(db=pg_db, vault_client=mock_vault_client, material_provider=provider)
        request = Mock(node_id=str(node_id), rotation_class="k8s-primary", key_version=1)
        context = FakeGrpcContext()

        async with app.app_context():
            response = await JoinerSecretsServicer().Emit(request, context)

        assert context.aborted is None
        assert response.secret_id
        row = pg_db(pg_db.joiner_secrets.id == response.secret_id).select().first()
        assert row is not None
        assert row.emitter_biome_id == biome_id
        assert row.tenant_id == "acme"

    async def test_emit_skips_non_emitting_biome_when_multiple_ready(
        self, pg_db: Any, mock_vault_client: Any
    ) -> None:
        """Regression (fix round 1): a node with two ``ready`` assignments --
        one pointing at a non-emitting biome, one at an emitting biome --
        must attribute the secret to the EMITTING biome, never whichever
        assignment happens to be most recent. Parity with
        ``JoinerSecretEmitter._load_context``'s ``emits_joiner_secrets``
        enforcement."""
        node_id = _seed_node(pg_db)
        non_emitting_id = _seed_biome(
            pg_db, biome_kind="sidecar", emits_joiner_secrets=False
        )
        emitting_id = _seed_biome(
            pg_db, biome_kind="k8s-primary", emits_joiner_secrets=True
        )
        # Non-emitting assignment inserted (and thus higher id) AFTER the
        # emitting one, so a naive "most recent ready row" pick would
        # select the wrong (non-emitting) biome.
        _seed_assignment(pg_db, node_id=node_id, egg_id=emitting_id, status="ready")
        _seed_assignment(pg_db, node_id=node_id, egg_id=non_emitting_id, status="ready")

        material = Mock()
        material.extractor_name = "grpc-emit"
        material.plaintext = b"fresh-token"
        material.ttl_seconds = 3600
        material.rotation_class = "single_use"
        provider = Mock(return_value=material)

        app = _make_app(db=pg_db, vault_client=mock_vault_client, material_provider=provider)
        request = Mock(node_id=str(node_id), rotation_class="k8s-primary", key_version=1)
        context = FakeGrpcContext()

        async with app.app_context():
            response = await JoinerSecretsServicer().Emit(request, context)

        assert context.aborted is None
        row = pg_db(pg_db.joiner_secrets.id == response.secret_id).select().first()
        assert row is not None
        assert row.emitter_biome_id == emitting_id

    async def test_emit_not_found_when_ready_assignment_biome_does_not_emit(
        self, pg_db: Any, mock_vault_client: Any
    ) -> None:
        """Regression (fix round 1): a node whose only ``ready`` assignment
        points at a non-emitting biome must abort NOT_FOUND, the same as
        having no ready assignment at all -- never persist a secret
        attributed to a biome that doesn't emit joiner secrets."""
        node_id = _seed_node(pg_db)
        biome_id = _seed_biome(pg_db, biome_kind="sidecar", emits_joiner_secrets=False)
        _seed_assignment(pg_db, node_id=node_id, egg_id=biome_id, status="ready")

        provider = Mock()
        app = _make_app(db=pg_db, vault_client=mock_vault_client, material_provider=provider)
        request = Mock(node_id=str(node_id), rotation_class="sidecar", key_version=1)
        context = FakeGrpcContext()

        async with app.app_context():
            with pytest.raises(_AbortCalled):
                await JoinerSecretsServicer().Emit(request, context)

        assert context.aborted is not None
        code, _details = context.aborted
        assert "NOT_FOUND" in str(code)
        provider.assert_not_called()

    async def test_emit_not_found_when_no_ready_assignment(
        self, pg_db: Any, mock_vault_client: Any
    ) -> None:
        node_id = _seed_node(pg_db)
        provider = Mock()
        app = _make_app(db=pg_db, vault_client=mock_vault_client, material_provider=provider)
        request = Mock(node_id=str(node_id), rotation_class="k8s-primary", key_version=1)
        context = FakeGrpcContext()

        async with app.app_context():
            with pytest.raises(_AbortCalled):
                await JoinerSecretsServicer().Emit(request, context)

        assert context.aborted is not None
        code, _details = context.aborted
        assert "NOT_FOUND" in str(code)
        provider.assert_not_called()

    async def test_emit_invalid_argument_on_bad_node_id(
        self, pg_db: Any, mock_vault_client: Any
    ) -> None:
        app = _make_app(db=pg_db, vault_client=mock_vault_client, material_provider=Mock())
        request = Mock(node_id="not-an-int", rotation_class="x", key_version=1)
        context = FakeGrpcContext()

        async with app.app_context():
            with pytest.raises(_AbortCalled):
                await JoinerSecretsServicer().Emit(request, context)

        code, _ = context.aborted
        assert "INVALID_ARGUMENT" in str(code)


# =============================================================================
# JoinerSecretsServicer.Consume
# =============================================================================


class TestConsume:
    async def test_consume_returns_real_plaintext(
        self, pg_db: Any, mock_vault_client: Any
    ) -> None:
        secret_id, plaintext = _seed_joiner_secret(
            pg_db, vault_client=mock_vault_client, plaintext=b"the-actual-secret"
        )
        app = _make_app(db=pg_db, vault_client=mock_vault_client)
        request = Mock(secret_id=secret_id, node_id="")
        context = FakeGrpcContext()

        async with app.app_context():
            response = await JoinerSecretsServicer().Consume(request, context)

        assert context.aborted is None
        # The whole point of the fix: decrypted_secret must be the REAL
        # plaintext, never the raw envelope ciphertext (see docstring on
        # JoinerSecretsServicer.Consume).
        assert response.decrypted_secret == plaintext
        assert response.decrypted_secret != b""

    async def test_consume_not_found(self, pg_db: Any, mock_vault_client: Any) -> None:
        app = _make_app(db=pg_db, vault_client=mock_vault_client)
        request = Mock(secret_id=str(uuid.uuid4()), node_id="")
        context = FakeGrpcContext()

        async with app.app_context():
            with pytest.raises(_AbortCalled):
                await JoinerSecretsServicer().Consume(request, context)

        code, _ = context.aborted
        assert "NOT_FOUND" in str(code)

    async def test_consume_revoked_denied(self, pg_db: Any, mock_vault_client: Any) -> None:
        secret_id, _ = _seed_joiner_secret(
            pg_db, vault_client=mock_vault_client, revoked_at=datetime.now(timezone.utc)
        )
        app = _make_app(db=pg_db, vault_client=mock_vault_client)
        request = Mock(secret_id=secret_id, node_id="")
        context = FakeGrpcContext()

        async with app.app_context():
            with pytest.raises(_AbortCalled):
                await JoinerSecretsServicer().Consume(request, context)

        code, _ = context.aborted
        assert "PERMISSION_DENIED" in str(code)


# =============================================================================
# JoinerSecretsServicer.Rotate
# =============================================================================


class TestRotate:
    async def test_rotate_atomic_success(self, pg_db: Any, mock_vault_client: Any) -> None:
        secret_id, _ = _seed_joiner_secret(pg_db, vault_client=mock_vault_client)

        material = Mock()
        material.extractor_name = "root-token"
        material.plaintext = b"new-material"
        material.ttl_seconds = 3600
        material.rotation_class = "vault-unseal"
        provider = Mock(return_value=material)

        app = _make_app(db=pg_db, vault_client=mock_vault_client, material_provider=provider)
        request = Mock(secret_id=secret_id, new_key_version=2)
        context = FakeGrpcContext()

        async with app.app_context():
            response = await JoinerSecretsServicer().Rotate(request, context)

        assert context.aborted is None
        assert response.new_secret_id
        assert response.new_secret_id != secret_id

        old_row = pg_db(pg_db.joiner_secrets.id == secret_id).select().first()
        new_row = pg_db(pg_db.joiner_secrets.id == response.new_secret_id).select().first()
        assert old_row.revoked_at is not None
        assert new_row is not None
        assert new_row.revoked_at is None

    async def test_rotate_rollback_on_persist_failure(
        self, pg_db: Any, mock_vault_client: Any
    ) -> None:
        """Forced Vault failure mid-transaction must NOT leave the old
        secret revoked with nothing to replace it (same regression class
        task 6a's fix-round-1 guarded for ``rotate_joiner_secret``)."""
        secret_id, _ = _seed_joiner_secret(pg_db, vault_client=mock_vault_client)

        material = Mock()
        material.extractor_name = "root-token"
        material.plaintext = b"new-material"
        material.ttl_seconds = 3600
        material.rotation_class = "vault-unseal"
        provider = Mock(return_value=material)

        failing_vault = Mock()
        failing_vault.transit_encrypt = Mock(side_effect=Exception("Vault sealed"))

        app = _make_app(db=pg_db, vault_client=failing_vault, material_provider=provider)
        request = Mock(secret_id=secret_id, new_key_version=2)
        context = FakeGrpcContext()

        async with app.app_context():
            with pytest.raises(_AbortCalled):
                await JoinerSecretsServicer().Rotate(request, context)

        code, _ = context.aborted
        assert "INTERNAL" in str(code)
        old_row = pg_db(pg_db.joiner_secrets.id == secret_id).select().first()
        assert old_row.revoked_at is None, "revoke must roll back with the failed persist"

    async def test_rotate_not_found(self, pg_db: Any, mock_vault_client: Any) -> None:
        app = _make_app(db=pg_db, vault_client=mock_vault_client, material_provider=Mock())
        request = Mock(secret_id=str(uuid.uuid4()), new_key_version=1)
        context = FakeGrpcContext()

        async with app.app_context():
            with pytest.raises(_AbortCalled):
                await JoinerSecretsServicer().Rotate(request, context)

        code, _ = context.aborted
        assert "NOT_FOUND" in str(code)

    async def test_rotate_already_revoked(self, pg_db: Any, mock_vault_client: Any) -> None:
        secret_id, _ = _seed_joiner_secret(
            pg_db, vault_client=mock_vault_client, revoked_at=datetime.now(timezone.utc)
        )
        app = _make_app(db=pg_db, vault_client=mock_vault_client, material_provider=Mock())
        request = Mock(secret_id=secret_id, new_key_version=1)
        context = FakeGrpcContext()

        async with app.app_context():
            with pytest.raises(_AbortCalled):
                await JoinerSecretsServicer().Rotate(request, context)

        code, _ = context.aborted
        assert "FAILED_PRECONDITION" in str(code)


# =============================================================================
# JoinerSecretsServicer.Revoke
# =============================================================================


class TestRevoke:
    async def test_revoke_marks_row(self, pg_db: Any, mock_vault_client: Any) -> None:
        secret_id, _ = _seed_joiner_secret(pg_db, vault_client=mock_vault_client)
        app = _make_app(db=pg_db)
        request = Mock(secret_id=secret_id)
        context = FakeGrpcContext()

        async with app.app_context():
            response = await JoinerSecretsServicer().Revoke(request, context)

        assert context.aborted is None
        assert response.revoked is True
        row = pg_db(pg_db.joiner_secrets.id == secret_id).select().first()
        assert row.revoked_at is not None

    async def test_revoke_already_revoked_returns_false(
        self, pg_db: Any, mock_vault_client: Any
    ) -> None:
        secret_id, _ = _seed_joiner_secret(
            pg_db, vault_client=mock_vault_client, revoked_at=datetime.now(timezone.utc)
        )
        app = _make_app(db=pg_db)
        request = Mock(secret_id=secret_id)
        context = FakeGrpcContext()

        async with app.app_context():
            response = await JoinerSecretsServicer().Revoke(request, context)

        assert context.aborted is None
        assert response.revoked is False

    async def test_revoke_not_found(self, pg_db: Any) -> None:
        app = _make_app(db=pg_db)
        request = Mock(secret_id=str(uuid.uuid4()))
        context = FakeGrpcContext()

        async with app.app_context():
            with pytest.raises(_AbortCalled):
                await JoinerSecretsServicer().Revoke(request, context)

        code, _ = context.aborted
        assert "NOT_FOUND" in str(code)


# =============================================================================
# JoinerSecretsServicer.List
# =============================================================================


class TestList:
    async def test_list_filters_by_node_and_paginates(
        self, pg_db: Any, mock_vault_client: Any
    ) -> None:
        node_id = _seed_node(pg_db)
        other_node_id = _seed_node(pg_db)
        _seed_joiner_secret(pg_db, vault_client=mock_vault_client, emitter_node_id=node_id)
        _seed_joiner_secret(pg_db, vault_client=mock_vault_client, emitter_node_id=node_id)
        _seed_joiner_secret(
            pg_db, vault_client=mock_vault_client, emitter_node_id=other_node_id
        )

        app = _make_app(db=pg_db)
        request = Mock(node_id=str(node_id), limit=1, cursor="")
        context = FakeGrpcContext()

        async with app.app_context():
            first_page = await JoinerSecretsServicer().List(request, context)

        assert context.aborted is None
        assert len(first_page.secrets) == 1
        assert first_page.next_cursor
        assert all(s.node_id == str(node_id) for s in first_page.secrets)

    async def test_list_empty_result(self, pg_db: Any) -> None:
        node_id = _seed_node(pg_db)
        app = _make_app(db=pg_db)
        request = Mock(node_id=str(node_id), limit=50, cursor="")
        context = FakeGrpcContext()

        async with app.app_context():
            response = await JoinerSecretsServicer().List(request, context)

        assert context.aborted is None
        assert list(response.secrets) == []
        assert response.next_cursor == ""

    async def test_list_invalid_node_id(self, pg_db: Any) -> None:
        app = _make_app(db=pg_db)
        request = Mock(node_id="not-an-int", limit=50, cursor="")
        context = FakeGrpcContext()

        async with app.app_context():
            with pytest.raises(_AbortCalled):
                await JoinerSecretsServicer().List(request, context)

        code, _ = context.aborted
        assert "INVALID_ARGUMENT" in str(code)


# =============================================================================
# AuditServicer.Stream / ExportRange
# =============================================================================


class TestAuditStream:
    async def test_stream_yields_events_since_offset(self, pg_db: Any) -> None:
        old_ts = datetime.now(timezone.utc) - timedelta(days=1)
        new_ts = datetime.now(timezone.utc)
        _seed_audit_event(pg_db, ts=old_ts, action="stale")
        _seed_audit_event(pg_db, ts=new_ts, action="fresh")

        app = _make_app(db=pg_db)
        cutoff = int((new_ts - timedelta(seconds=1)).timestamp())
        request = Mock(start_offset=cutoff, filter="")
        context = FakeGrpcContext()

        async with app.app_context():
            results = [r async for r in AuditServicer().Stream(request, context)]

        assert context.aborted is None
        assert len(results) == 1
        payload = json.loads(results[0].event_payload)
        assert payload["action"] == "fresh"

    async def test_stream_applies_after_json_filter(self, pg_db: Any) -> None:
        _seed_audit_event(
            pg_db, action="match", after_json={"biome_kind": "vault"}
        )
        _seed_audit_event(
            pg_db, action="no-match", after_json={"biome_kind": "other"}
        )

        app = _make_app(db=pg_db)
        request = Mock(
            start_offset=0, filter=json.dumps({"biome_kind": "vault"})
        )
        context = FakeGrpcContext()

        async with app.app_context():
            results = [r async for r in AuditServicer().Stream(request, context)]

        assert [json.loads(r.event_payload)["action"] for r in results] == ["match"]

    async def test_stream_empty_result(self, pg_db: Any) -> None:
        app = _make_app(db=pg_db)
        request = Mock(start_offset=int(datetime.now(timezone.utc).timestamp()) + 3600, filter="")
        context = FakeGrpcContext()

        async with app.app_context():
            results = [r async for r in AuditServicer().Stream(request, context)]

        assert results == []


class TestAuditExportRange:
    async def test_export_range_returns_jsonl(self, pg_db: Any) -> None:
        now = datetime.now(timezone.utc)
        _seed_audit_event(pg_db, ts=now, action="in-range")
        _seed_audit_event(pg_db, ts=now - timedelta(days=2), action="out-of-range")

        app = _make_app(db=pg_db)
        request = Mock(
            start_time=int((now - timedelta(hours=1)).timestamp()),
            end_time=int((now + timedelta(hours=1)).timestamp()),
            format="jsonl",
        )
        context = FakeGrpcContext()

        async with app.app_context():
            response = await AuditServicer().ExportRange(request, context)

        assert context.aborted is None
        lines = response.export_data.decode("utf-8").splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["action"] == "in-range"

    async def test_export_range_empty_result(self, pg_db: Any) -> None:
        now = datetime.now(timezone.utc)
        app = _make_app(db=pg_db)
        request = Mock(
            start_time=int(now.timestamp()) + 3600,
            end_time=int(now.timestamp()) + 7200,
            format="jsonl",
        )
        context = FakeGrpcContext()

        async with app.app_context():
            response = await AuditServicer().ExportRange(request, context)

        assert response.export_data == b""


# =============================================================================
# IdentityServicer.VerifyOTPN
# =============================================================================


class TestVerifyOTPN:
    async def test_verify_otpn_success_returns_real_plaintext(
        self, pg_db: Any, mock_vault_client: Any
    ) -> None:
        node_id = _seed_node(pg_db)
        _seed_joiner_secret(
            pg_db,
            vault_client=mock_vault_client,
            plaintext=b"otpn-material",
            emitter_node_id=node_id,
            rotation_class="single_use",
        )

        app = _make_app(db=pg_db, vault_client=mock_vault_client)
        request = Mock(node_id=str(node_id), otp_token="unused", rotation_class="single_use")
        context = FakeGrpcContext()

        async with app.app_context():
            response = await IdentityServicer().VerifyOTPN(request, context)

        assert context.aborted is None
        assert response.valid is True
        assert response.decrypted_secret == b"otpn-material"

    async def test_verify_otpn_not_found_returns_false_not_error(
        self, pg_db: Any, mock_vault_client: Any
    ) -> None:
        node_id = _seed_node(pg_db)
        app = _make_app(db=pg_db, vault_client=mock_vault_client)
        request = Mock(node_id=str(node_id), otp_token="x", rotation_class="single_use")
        context = FakeGrpcContext()

        async with app.app_context():
            response = await IdentityServicer().VerifyOTPN(request, context)

        assert context.aborted is None
        assert response.valid is False
        assert response.decrypted_secret == b""

    async def test_verify_otpn_revoked_returns_false(
        self, pg_db: Any, mock_vault_client: Any
    ) -> None:
        node_id = _seed_node(pg_db)
        _seed_joiner_secret(
            pg_db,
            vault_client=mock_vault_client,
            emitter_node_id=node_id,
            rotation_class="single_use",
            revoked_at=datetime.now(timezone.utc),
        )
        app = _make_app(db=pg_db, vault_client=mock_vault_client)
        request = Mock(node_id=str(node_id), otp_token="x", rotation_class="single_use")
        context = FakeGrpcContext()

        async with app.app_context():
            response = await IdentityServicer().VerifyOTPN(request, context)

        assert response.valid is False

    async def test_verify_otpn_invalid_node_id_returns_false_not_error(
        self, pg_db: Any, mock_vault_client: Any
    ) -> None:
        app = _make_app(db=pg_db, vault_client=mock_vault_client)
        request = Mock(node_id="not-an-int", otp_token="x", rotation_class="single_use")
        context = FakeGrpcContext()

        async with app.app_context():
            response = await IdentityServicer().VerifyOTPN(request, context)

        assert context.aborted is None
        assert response.valid is False


# =============================================================================
# RLS proof: _cross_tenant_scope is what makes these RPCs see rows at all
# =============================================================================


class TestCrossTenantScopeRLS:
    async def test_consume_sees_row_under_scoped_role_only_via_cross_tenant_scope(
        self, pg_db: Any, pg_db_scoped: Any, mock_vault_client: Any
    ) -> None:
        """Proves ``_cross_tenant_scope()`` -- not an app-level filter, since
        Consume has none -- is what lets the scoped ``api-manager-rw`` role
        see this row at all under RLS.

        Negative control first (RLS genuinely active for this role, absent
        the scope): a direct scoped-role read with no tenant ContextVar set
        must return zero rows (fail closed, same proof style as
        ``tests/test_rls_isolation.py``). Positive: the real servicer
        method, which does apply the scope internally, finds it.
        """
        from app.db.rls import install_rls_events

        secret_id, plaintext = _seed_joiner_secret(
            pg_db, vault_client=mock_vault_client, tenant_id="acme"
        )
        install_rls_events(pg_db_scoped.engine)

        # Negative control: no tenant context set at all on this task ->
        # fail-closed sentinel -> RLS must filter this out for the scoped role.
        direct = pg_db_scoped(pg_db_scoped.joiner_secrets.id == secret_id).select().first()
        assert direct is None, "RLS did not filter the scoped role -- test is not proving anything"

        # Positive: the real servicer path applies _cross_tenant_scope() itself.
        app = _make_app(db=pg_db_scoped, vault_client=mock_vault_client)
        request = Mock(secret_id=secret_id, node_id="")
        context = FakeGrpcContext()

        async with app.app_context():
            response = await JoinerSecretsServicer().Consume(request, context)

        assert context.aborted is None
        assert response.decrypted_secret == plaintext
