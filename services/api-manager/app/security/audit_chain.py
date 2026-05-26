"""Audit chain — hash-chained immutable audit log.

Per Gough spec Observability → Audit Log Hash-Chain Format. UUIDv7 IDs;
RFC 8785 JCS canonicalization; SHA-256 chain hash; optional Vault-transit
signature (Ed25519 enterprise / ECDSA P-256 fedramp lane).

Genesis row insertion is handled by `gough init` at cluster bootstrap.
"""

import hashlib
import json
import secrets
import threading as _threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from pydantic import BaseModel


GENESIS_ID = uuid.UUID('00000000-0000-7000-8000-000000000000')
ZERO_HASH = b'\x00' * 32

_uuidv7_lock = _threading.Lock()
_uuidv7_state: dict = {"last_ms": 0, "seq": 0}


def generate_uuidv7() -> uuid.UUID:
    """Generate RFC 9562 UUIDv7 with monotonic sub-ms sequence."""
    with _uuidv7_lock:
        ts_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF
        if ts_ms > _uuidv7_state["last_ms"]:
            _uuidv7_state["last_ms"] = ts_ms
            _uuidv7_state["seq"] = secrets.randbits(12)
        else:
            ts_ms = _uuidv7_state["last_ms"]
            _uuidv7_state["seq"] = (_uuidv7_state["seq"] + 1) & 0xFFF
        seq = _uuidv7_state["seq"]

    rand_62 = secrets.randbits(62)
    return uuid.UUID(
        fields=(
            (ts_ms >> 16) & 0xFFFFFFFF,
            ts_ms & 0xFFFF,
            0x7000 | seq,
            0x80 | ((rand_62 >> 56) & 0x3F),
            (rand_62 >> 48) & 0xFF,
            rand_62 & 0xFFFFFFFFFFFF,
        )
    )


def canonicalize_record(fields: dict[str, Any]) -> bytes:
    """RFC 8785 JCS: sorted keys, compact JSON, reject NaN/Inf."""
    def check_valid(obj: Any) -> Any:
        if isinstance(obj, float):
            if obj != obj or obj == float('inf') or obj == float('-inf'):
                raise ValueError(f"NaN/Inf not allowed in JCS: {obj}")
        elif isinstance(obj, dict):
            return {k: check_valid(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [check_valid(v) for v in obj]
        return obj

    check_valid(fields)
    return json.dumps(
        fields, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, default=str
    ).encode('utf-8')


def compute_chain_hash(prev_hash: bytes, record_fields: dict[str, Any]) -> bytes:
    """SHA-256(prev_hash || JCS(record_fields)). prev_hash must be 32 bytes."""
    if len(prev_hash) != 32:
        raise ValueError(f"prev_hash must be 32 bytes, got {len(prev_hash)}")
    canonical = canonicalize_record(record_fields)
    return hashlib.sha256(prev_hash + canonical).digest()


class AuditEvent(BaseModel):
    """Audit event record."""
    id: uuid.UUID
    ts: datetime
    cluster_id: str
    tenant_id: Optional[str] = None
    actor_sub: str
    actor_scope: list[str]
    action: str
    resource_kind: str
    resource_id: Optional[str] = None
    before_json: Optional[dict[str, Any]] = None
    after_json: Optional[dict[str, Any]] = None
    request_id: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    prev_hash: bytes
    hash: bytes
    signature: Optional[bytes] = None


class AuditEventWriter:
    """Single-writer leader: appends audit events with chain hash."""

    def __init__(
        self,
        db_session: Any,
        cluster_id: str,
        signer: Optional[Callable[[bytes], bytes]] = None,
    ) -> None:
        """Initialize writer. signer: optional Vault-transit Ed25519 signer."""
        self.db_session = db_session
        self.cluster_id = cluster_id
        self.signer = signer

    def append(
        self,
        *,
        actor_sub: str,
        action: str,
        resource_kind: str,
        resource_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        actor_scope: Optional[list[str]] = None,
        before: Optional[dict[str, Any]] = None,
        after: Optional[dict[str, Any]] = None,
        request_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditEvent:
        """Append audit event; fetch latest hash; compute chain hash; optionally sign."""
        from sqlalchemy import text

        actor_scope = actor_scope or []

        row = self.db_session.execute(
            text('SELECT hash FROM audit_events ORDER BY ts DESC, id DESC LIMIT 1')
        ).first()
        prev_hash_raw = row[0] if row else None
        prev_hash = (
            prev_hash_raw
            if isinstance(prev_hash_raw, (bytes, bytearray)) and len(prev_hash_raw) == 32
            else ZERO_HASH
        )

        event_id = generate_uuidv7()
        ts_utc = datetime.now(timezone.utc)

        record_fields = {
            'id': str(event_id),
            'ts': ts_utc.isoformat(),
            'cluster_id': self.cluster_id,
            'tenant_id': tenant_id,
            'actor_sub': actor_sub,
            'actor_scope': actor_scope,
            'action': action,
            'resource_kind': resource_kind,
            'resource_id': resource_id,
            'before_json': before,
            'after_json': after,
            'request_id': request_id,
            'source_ip': source_ip,
            'user_agent': user_agent,
        }

        chain_hash = compute_chain_hash(prev_hash, record_fields)
        signature = self.signer(chain_hash) if self.signer else None

        stmt = text('''
            INSERT INTO audit_events
            (id, ts, cluster_id, tenant_id, actor_sub, actor_scope, action,
             resource_kind, resource_id, before_json, after_json, request_id,
             source_ip, user_agent, prev_hash, hash, signature)
            VALUES
            (:id, :ts, :cluster_id, :tenant_id, :actor_sub, :actor_scope,
             :action, :resource_kind, :resource_id, :before_json, :after_json,
             :request_id, :source_ip, :user_agent, :prev_hash, :hash, :signature)
        ''')

        self.db_session.execute(
            stmt,
            {
                'id': str(event_id),
                'ts': ts_utc,
                'cluster_id': self.cluster_id,
                'tenant_id': tenant_id,
                'actor_sub': actor_sub,
                'actor_scope': json.dumps(actor_scope),
                'action': action,
                'resource_kind': resource_kind,
                'resource_id': resource_id,
                'before_json': json.dumps(before) if before else None,
                'after_json': json.dumps(after) if after else None,
                'request_id': request_id,
                'source_ip': source_ip,
                'user_agent': user_agent,
                'prev_hash': prev_hash,
                'hash': chain_hash,
                'signature': signature,
            },
        )

        return AuditEvent(
            id=event_id,
            ts=ts_utc,
            cluster_id=self.cluster_id,
            tenant_id=tenant_id,
            actor_sub=actor_sub,
            actor_scope=actor_scope,
            action=action,
            resource_kind=resource_kind,
            resource_id=resource_id,
            before_json=before,
            after_json=after,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
            prev_hash=prev_hash,
            hash=chain_hash,
            signature=signature,
        )


def verify_chain(
    db_session: Any,
    since: Optional[datetime] = None,
    to: Optional[datetime] = None,
) -> dict[str, Any]:
    """Verify chain integrity: recompute hashes, detect breaks."""
    from sqlalchemy import text

    query = (
        'SELECT id, ts, cluster_id, tenant_id, actor_sub, actor_scope, action, '
        'resource_kind, resource_id, before_json, after_json, request_id, '
        'source_ip, user_agent, prev_hash, hash FROM audit_events'
    )
    params = {}
    conditions = []

    if since:
        conditions.append('ts >= :since')
        params['since'] = since
    if to:
        conditions.append('ts <= :to')
        params['to'] = to

    if conditions:
        query += ' WHERE ' + ' AND '.join(conditions)

    query += ' ORDER BY ts ASC, id ASC'

    rows = db_session.execute(text(query), params).fetchall()

    rows_checked = 0
    breaks = 0
    first_break_id = None
    last_break_id = None

    for row in rows:
        (
            event_id, ts, cluster_id, tenant_id, actor_sub, actor_scope, action,
            resource_kind, resource_id, before_json, after_json, request_id,
            source_ip, user_agent, stored_prev, stored_hash,
        ) = row
        record_fields = {
            'id': str(event_id),
            'ts': ts.isoformat() if hasattr(ts, 'isoformat') else str(ts),
            'cluster_id': cluster_id or '',
            'tenant_id': tenant_id,
            'actor_sub': actor_sub,
            'actor_scope': actor_scope if isinstance(actor_scope, list) else [],
            'action': action,
            'resource_kind': resource_kind,
            'resource_id': resource_id,
            'before_json': before_json,
            'after_json': after_json,
            'request_id': request_id,
            'source_ip': source_ip,
            'user_agent': user_agent,
        }

        computed_hash = compute_chain_hash(stored_prev, record_fields)
        rows_checked += 1

        if computed_hash != stored_hash:
            breaks += 1
            if first_break_id is None:
                first_break_id = event_id
            last_break_id = event_id

    return {
        'rows_checked': rows_checked,
        'breaks': breaks,
        'first_break_id': first_break_id,
        'last_break_id': last_break_id,
    }


def insert_genesis_row(db_session: Any, cluster_id: str) -> AuditEvent:
    """Idempotent genesis: returns existing or inserts new."""
    from sqlalchemy import text

    row = db_session.execute(
        text('SELECT hash FROM audit_events WHERE id = :id'),
        {'id': str(GENESIS_ID)},
    ).first()

    if row:
        return AuditEvent(
            id=GENESIS_ID,
            ts=datetime.now(timezone.utc),
            cluster_id=cluster_id,
            actor_sub='system',
            actor_scope=['system:admin'],
            action='cluster_init',
            resource_kind='cluster',
            prev_hash=ZERO_HASH,
            hash=row[0],
        )

    genesis_hash = hashlib.sha256(
        b'gough-cluster-genesis:' + cluster_id.encode('utf-8')
    ).digest()

    stmt = text('''
        INSERT INTO audit_events
        (id, ts, cluster_id, actor_sub, actor_scope, action, resource_kind,
         prev_hash, hash)
        VALUES
        (:id, :ts, :cluster_id, :actor_sub, :actor_scope, :action,
         :resource_kind, :prev_hash, :hash)
    ''')

    db_session.execute(
        stmt,
        {
            'id': str(GENESIS_ID),
            'ts': datetime.now(timezone.utc),
            'cluster_id': cluster_id,
            'actor_sub': 'system',
            'actor_scope': json.dumps(['system:admin']),
            'action': 'cluster_init',
            'resource_kind': 'cluster',
            'prev_hash': ZERO_HASH,
            'hash': genesis_hash,
        },
    )

    return AuditEvent(
        id=GENESIS_ID,
        ts=datetime.now(timezone.utc),
        cluster_id=cluster_id,
        actor_sub='system',
        actor_scope=['system:admin'],
        action='cluster_init',
        resource_kind='cluster',
        prev_hash=ZERO_HASH,
        hash=genesis_hash,
    )
