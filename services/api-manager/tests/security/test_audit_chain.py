"""Tests for audit_chain: UUIv7, JCS canonicalization, hash-chain verification."""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from app.security.audit_chain import (
    GENESIS_ID,
    ZERO_HASH,
    AuditEvent,
    AuditEventWriter,
    canonicalize_record,
    compute_chain_hash,
    generate_uuidv7,
    insert_genesis_row,
    verify_chain,
)


class TestGenerateUUIDv7:
    """UUIDv7 generation and ordering."""

    def test_generate_uuidv7_is_time_ordered(self) -> None:
        """Generate 100 UUIDs; sorting by bytes preserves generation order."""
        uuids = [generate_uuidv7() for _ in range(100)]
        sorted_uuids = sorted(uuids, key=lambda u: u.bytes)
        assert sorted_uuids == uuids, "UUIDs must be time-ordered"

    def test_generate_uuidv7_version_7(self) -> None:
        """Generated UUIDs have version 7 marker in time_hi_version field."""
        u = generate_uuidv7()
        assert (u.time_hi_version >> 12) == 7, "Version must be 7"

    def test_generate_uuidv7_variant_rfc(self) -> None:
        """Generated UUIDs have RFC 4122 variant (10xxxxxx)."""
        u = generate_uuidv7()
        variant_bits = (u.clock_seq_hi_variant >> 6) & 0b11
        assert variant_bits == 0b10, "Variant must be RFC 4122 (10)"


class TestCanonicalizeRecord:
    """RFC 8785 JCS canonicalization."""

    def test_canonicalize_record_sorted_keys(self) -> None:
        """Out-of-order input keys are sorted lexicographically."""
        record = {'z': 1, 'a': 2, 'm': 3}
        canonical = canonicalize_record(record)
        expected = b'{"a":2,"m":3,"z":1}'
        assert canonical == expected

    def test_canonicalize_record_no_whitespace(self) -> None:
        """Canonical form is compact: no spaces, separators minimal."""
        record = {'key': 'value', 'num': 42}
        canonical = canonicalize_record(record)
        assert b' ' not in canonical, "Must be compact (no spaces)"
        assert canonical == b'{"key":"value","num":42}'

    def test_canonicalize_record_nested_objects(self) -> None:
        """Nested objects are also sorted."""
        record = {'outer': {'z': 1, 'a': 2}}
        canonical = canonicalize_record(record)
        assert canonical == b'{"outer":{"a":2,"z":1}}'

    def test_canonicalize_record_arrays(self) -> None:
        """Arrays are preserved as-is (order matters)."""
        record = {'items': [3, 1, 2]}
        canonical = canonicalize_record(record)
        assert canonical == b'{"items":[3,1,2]}'

    def test_canonicalize_record_rejects_nan(self) -> None:
        """NaN raises ValueError or JSONEncodeError."""
        record = {'value': float('nan')}
        with pytest.raises((ValueError, json.JSONDecodeError)):
            canonicalize_record(record)

    def test_canonicalize_record_rejects_infinity(self) -> None:
        """Infinity raises ValueError or JSONEncodeError."""
        record = {'value': float('inf')}
        with pytest.raises((ValueError, json.JSONDecodeError)):
            canonicalize_record(record)

    def test_canonicalize_record_null_true_false(self) -> None:
        """null, true, false lowercased."""
        record = {'a': None, 'b': True, 'c': False}
        canonical = canonicalize_record(record)
        assert b'null' in canonical
        assert b'true' in canonical
        assert b'false' in canonical


class TestComputeChainHash:
    """SHA-256 chain hash computation."""

    def test_compute_chain_hash_deterministic(self) -> None:
        """Same input always produces same output."""
        prev = ZERO_HASH
        record = {'action': 'test', 'id': '123'}
        h1 = compute_chain_hash(prev, record)
        h2 = compute_chain_hash(prev, record)
        assert h1 == h2
        assert len(h1) == 32

    def test_compute_chain_hash_validates_prev_length(self) -> None:
        """prev_hash must be exactly 32 bytes."""
        short_prev = b'\x00' * 31
        record = {'action': 'test'}
        with pytest.raises(ValueError, match="32 bytes"):
            compute_chain_hash(short_prev, record)

    def test_compute_chain_hash_chains(self) -> None:
        """Small chain of 3 records: hashes link correctly."""
        h0 = ZERO_HASH
        rec1 = {'action': 'create', 'id': '1'}
        h1 = compute_chain_hash(h0, rec1)

        rec2 = {'action': 'update', 'id': '2'}
        h2 = compute_chain_hash(h1, rec2)

        rec3 = {'action': 'delete', 'id': '3'}
        h3 = compute_chain_hash(h2, rec3)

        assert h1 != h0
        assert h2 != h1
        assert h3 != h2
        assert len(h3) == 32

    def test_compute_chain_hash_different_records_different_hash(self) -> None:
        """Different records produce different hashes."""
        prev = ZERO_HASH
        h1 = compute_chain_hash(prev, {'value': 'a'})
        h2 = compute_chain_hash(prev, {'value': 'b'})
        assert h1 != h2

    def test_compute_chain_hash_different_prev_different_hash(self) -> None:
        """Different prev_hash produces different result."""
        record = {'action': 'test'}
        h1 = compute_chain_hash(ZERO_HASH, record)
        h2 = compute_chain_hash(b'\xFF' * 32, record)
        assert h1 != h2


class TestAuditEventWriter:
    """AuditEventWriter: append events with chain linking."""

    def test_audit_event_writer_first_event_uses_zero_prev(self) -> None:
        """First event (empty audit_events) uses ZERO_HASH as prev."""
        db_session = MagicMock()
        db_session.execute.return_value.first.return_value = None

        writer = AuditEventWriter(db_session, 'test-cluster')
        event = writer.append(
            actor_sub='user@example.com',
            action='test_action',
            resource_kind='resource',
        )

        assert event.prev_hash == ZERO_HASH

    def test_audit_event_writer_subsequent_event_links_to_last(self) -> None:
        """Subsequent event's prev_hash matches last row's hash."""
        last_hash = b'\xAA' * 32
        db_session = MagicMock()
        db_session.execute.return_value.first.return_value = (last_hash,)

        writer = AuditEventWriter(db_session, 'test-cluster')
        event = writer.append(
            actor_sub='user@example.com',
            action='test_action',
            resource_kind='resource',
        )

        assert event.prev_hash == last_hash

    def test_audit_event_writer_with_signer(self) -> None:
        """With signer, signature is populated."""
        db_session = MagicMock()
        db_session.execute.return_value.first.return_value = None

        def mock_signer(data: bytes) -> bytes:
            return hashlib.sha256(b'sig_' + data).digest()

        writer = AuditEventWriter(db_session, 'test-cluster', signer=mock_signer)
        event = writer.append(
            actor_sub='user@example.com',
            action='test_action',
            resource_kind='resource',
        )

        assert event.signature is not None
        assert len(event.signature) == 32

    def test_audit_event_writer_without_signer(self) -> None:
        """Without signer, signature is None."""
        db_session = MagicMock()
        db_session.execute.return_value.first.return_value = None

        writer = AuditEventWriter(db_session, 'test-cluster', signer=None)
        event = writer.append(
            actor_sub='user@example.com',
            action='test_action',
            resource_kind='resource',
        )

        assert event.signature is None

    def test_audit_event_writer_append_returns_audit_event(self) -> None:
        """append() returns AuditEvent with all fields populated."""
        db_session = MagicMock()
        db_session.execute.return_value.first.return_value = None

        writer = AuditEventWriter(db_session, 'test-cluster')
        event = writer.append(
            actor_sub='user@example.com',
            action='create',
            resource_kind='user',
            resource_id='user-123',
            tenant_id='tenant-xyz',
            actor_scope=['read', 'write'],
            before={'count': 0},
            after={'count': 1},
            request_id='req-abc',
            source_ip='192.168.1.1',
            user_agent='Mozilla/5.0',
        )

        assert isinstance(event, AuditEvent)
        assert event.actor_sub == 'user@example.com'
        assert event.action == 'create'
        assert event.resource_kind == 'user'
        assert event.resource_id == 'user-123'
        assert event.tenant_id == 'tenant-xyz'
        assert event.actor_scope == ['read', 'write']
        assert event.before_json == {'count': 0}
        assert event.after_json == {'count': 1}
        assert event.request_id == 'req-abc'
        assert event.source_ip == '192.168.1.1'
        assert event.user_agent == 'Mozilla/5.0'


class TestVerifyChain:
    """verify_chain: integrity checking."""

    def test_verify_chain_passes_for_clean(self) -> None:
        """Clean chain: verify_chain returns 0 breaks."""
        h0 = ZERO_HASH

        event_id_1 = uuid.uuid4()
        ts_1 = datetime.now(timezone.utc)
        record_fields_1 = {
            'id': str(event_id_1),
            'ts': ts_1.isoformat(),
            'cluster_id': 'test-cluster',
            'tenant_id': 'default',
            'actor_sub': 'user@example.com',
            'actor_scope': [],
            'action': 'create',
            'resource_kind': 'resource',
            'resource_id': None,
            'before_json': None,
            'after_json': None,
            'request_id': None,
            'source_ip': None,
            'user_agent': None,
        }
        h1 = compute_chain_hash(h0, record_fields_1)

        event_id_2 = uuid.uuid4()
        ts_2 = datetime.now(timezone.utc)
        record_fields_2 = {
            'id': str(event_id_2),
            'ts': ts_2.isoformat(),
            'cluster_id': 'test-cluster',
            'tenant_id': 'default',
            'actor_sub': 'user@example.com',
            'actor_scope': [],
            'action': 'update',
            'resource_kind': 'resource',
            'resource_id': None,
            'before_json': None,
            'after_json': None,
            'request_id': None,
            'source_ip': None,
            'user_agent': None,
        }
        h2 = compute_chain_hash(h1, record_fields_2)

        rows = [
            (
                event_id_1,
                ts_1,
                'test-cluster',
                'default',
                'user@example.com',
                [],
                'create',
                'resource',
                None,
                None,
                None,
                None,
                None,
                None,
                h0,
                h1,
            ),
            (
                event_id_2,
                ts_2,
                'test-cluster',
                'default',
                'user@example.com',
                [],
                'update',
                'resource',
                None,
                None,
                None,
                None,
                None,
                None,
                h1,
                h2,
            ),
        ]

        db_session = MagicMock()
        db_session.execute.return_value.fetchall.return_value = rows

        result = verify_chain(db_session, since=None, to=None)

        assert result['rows_checked'] == 2
        assert result['breaks'] == 0
        assert result['first_break_id'] is None
        assert result['last_break_id'] is None

    def test_verify_chain_detects_tamper(self) -> None:
        """One row's hash mutated: verify_chain detects break."""
        h0 = ZERO_HASH

        event_id_1 = uuid.uuid4()
        ts_1 = datetime.now(timezone.utc)
        record_fields_1 = {
            'id': str(event_id_1),
            'ts': ts_1.isoformat(),
            'cluster_id': 'test-cluster',
            'tenant_id': 'default',
            'actor_sub': 'user@example.com',
            'actor_scope': [],
            'action': 'create',
            'resource_kind': 'resource',
            'resource_id': None,
            'before_json': None,
            'after_json': None,
            'request_id': None,
            'source_ip': None,
            'user_agent': None,
        }
        h1 = compute_chain_hash(h0, record_fields_1)

        event_id_2 = uuid.uuid4()
        ts_2 = datetime.now(timezone.utc)
        record_fields_2 = {
            'id': str(event_id_2),
            'ts': ts_2.isoformat(),
            'cluster_id': 'test-cluster',
            'tenant_id': 'default',
            'actor_sub': 'user@example.com',
            'actor_scope': [],
            'action': 'update',
            'resource_kind': 'resource',
            'resource_id': None,
            'before_json': None,
            'after_json': None,
            'request_id': None,
            'source_ip': None,
            'user_agent': None,
        }
        h2 = compute_chain_hash(h1, record_fields_2)
        mutated_h2 = b'\xFF' * 32

        rows = [
            (
                event_id_1,
                ts_1,
                'test-cluster',
                'default',
                'user@example.com',
                [],
                'create',
                'resource',
                None,
                None,
                None,
                None,
                None,
                None,
                h0,
                h1,
            ),
            (
                event_id_2,
                ts_2,
                'test-cluster',
                'default',
                'user@example.com',
                [],
                'update',
                'resource',
                None,
                None,
                None,
                None,
                None,
                None,
                h1,
                mutated_h2,
            ),
        ]

        db_session = MagicMock()
        db_session.execute.return_value.fetchall.return_value = rows

        result = verify_chain(db_session, since=None, to=None)

        assert result['breaks'] == 1
        assert result['first_break_id'] == event_id_2
        assert result['last_break_id'] == event_id_2


class TestInsertGenesisRow:
    """insert_genesis_row: idempotent cluster initialization."""

    def test_insert_genesis_row_idempotent(self) -> None:
        """Call twice: only one genesis exists (idempotent)."""
        db_session = MagicMock()

        db_session.execute.return_value.first.side_effect = [
            None,
            (hashlib.sha256(b'gough-cluster-genesis:test-cluster').digest(),),
        ]

        genesis1 = insert_genesis_row(db_session, 'test-cluster')
        assert genesis1.id == GENESIS_ID

        genesis2 = insert_genesis_row(db_session, 'test-cluster')
        assert genesis2.id == GENESIS_ID
        assert genesis1.hash == genesis2.hash

    def test_genesis_row_id_constant(self) -> None:
        """insert_genesis_row produces id == GENESIS_ID."""
        db_session = MagicMock()
        db_session.execute.return_value.first.return_value = None

        genesis = insert_genesis_row(db_session, 'test-cluster')
        assert genesis.id == GENESIS_ID

    def test_genesis_row_hash_deterministic(self) -> None:
        """Genesis hash is deterministic: sha256('gough-cluster-genesis:' + cluster_id)."""
        cluster_id = 'test-cluster'
        expected_hash = hashlib.sha256(
            b'gough-cluster-genesis:' + cluster_id.encode('utf-8')
        ).digest()

        db_session = MagicMock()
        db_session.execute.return_value.first.return_value = None

        genesis = insert_genesis_row(db_session, cluster_id)
        assert genesis.hash == expected_hash

    def test_genesis_row_prev_hash_zero(self) -> None:
        """Genesis prev_hash is ZERO_HASH."""
        db_session = MagicMock()
        db_session.execute.return_value.first.return_value = None

        genesis = insert_genesis_row(db_session, 'test-cluster')
        assert genesis.prev_hash == ZERO_HASH
