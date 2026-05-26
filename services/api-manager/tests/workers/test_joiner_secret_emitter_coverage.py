"""Extended coverage tests for joiner_secret_emitter.py missed lines."""

import pytest
from unittest.mock import MagicMock, Mock
from datetime import datetime, timezone

from app.workers.joiner_secret_emitter import (
    JoinerSecretEmitter,
    ExtractorSpecError,
    ControlTunnelExtractionError,
    EmitterStateError,
    _mask,
)
from app.models_m1 import Biome, Node, NodeBiomeAssignment


class TestMaskFunction:
    """Test _mask helper for sanitized logging."""

    def test_mask_none(self):
        """_mask returns '<none>' for None."""
        assert _mask(None) == "<none>"

    def test_mask_bytes(self):
        """_mask returns length for bytes."""
        result = _mask(b"secret data")
        assert result == "<bytes len=11>"

    def test_mask_bytearray(self):
        """_mask returns length for bytearray."""
        result = _mask(bytearray(b"secret"))
        assert result == "<bytes len=6>"  # memoryview/bytearray treated as bytes

    def test_mask_str(self):
        """_mask returns length for str."""
        result = _mask("secret string")
        assert result == "<str len=13>"

    def test_mask_other_type(self):
        """_mask returns type name for other types."""
        result = _mask(12345)
        assert result == "<int>"


class TestJoinerSecretEmitterLoadContext:
    """Test context loading and validation."""

    def test_load_context_assignment_not_found(self):
        """_load_context raises when assignment missing."""
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.one_or_none.return_value = None

        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        with pytest.raises(EmitterStateError, match="not found"):
            emitter._load_context(999)

    def test_load_context_assignment_not_ready(self):
        """_load_context raises when assignment status not 'ready'."""
        mock_db = MagicMock()
        mock_assignment = MagicMock()
        mock_assignment.status = "provisioning"
        mock_db.query.return_value.filter.return_value.one_or_none.return_value = mock_assignment

        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        with pytest.raises(EmitterStateError, match="status is"):
            emitter._load_context(1)

    def test_load_context_biome_not_found(self):
        """_load_context raises when biome missing."""
        mock_db = MagicMock()
        mock_assignment = MagicMock()
        mock_assignment.status = "ready"
        mock_assignment.biome_id = 1

        mock_query = MagicMock()
        mock_query.filter.return_value.one_or_none.side_effect = [
            mock_assignment,  # Assignment
            None,  # Biome not found
        ]
        mock_db.query.return_value = mock_query

        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        with pytest.raises(EmitterStateError, match="biome"):
            emitter._load_context(1)

    def test_load_context_biome_not_emitting(self):
        """_load_context raises when biome.emits_joiner_secrets is False."""
        mock_db = MagicMock()
        mock_assignment = MagicMock()
        mock_assignment.status = "ready"
        mock_assignment.biome_id = 1
        mock_assignment.node_id = 2

        mock_biome = MagicMock()
        mock_biome.id = 1
        mock_biome.emits_joiner_secrets = False

        mock_query = MagicMock()
        mock_query.filter.return_value.one_or_none.side_effect = [
            mock_assignment,  # Assignment
            mock_biome,  # Biome
        ]
        mock_db.query.return_value = mock_query

        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        with pytest.raises(EmitterStateError, match="emits_joiner_secrets=false"):
            emitter._load_context(1)

    def test_load_context_node_not_found(self):
        """_load_context raises when node missing."""
        mock_db = MagicMock()
        mock_assignment = MagicMock()
        mock_assignment.status = "ready"
        mock_assignment.biome_id = 1
        mock_assignment.node_id = 2

        mock_biome = MagicMock()
        mock_biome.id = 1
        mock_biome.emits_joiner_secrets = True

        mock_query = MagicMock()
        mock_query.filter.return_value.one_or_none.side_effect = [
            mock_assignment,  # Assignment
            mock_biome,  # Biome
            None,  # Node not found
        ]
        mock_db.query.return_value = mock_query

        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        with pytest.raises(EmitterStateError, match="node"):
            emitter._load_context(1)

    def test_load_context_success(self):
        """_load_context returns assignment, biome, node when valid."""
        mock_db = MagicMock()
        mock_assignment = MagicMock()
        mock_assignment.status = "ready"
        mock_assignment.biome_id = 1
        mock_assignment.node_id = 2

        mock_biome = MagicMock()
        mock_biome.id = 1
        mock_biome.emits_joiner_secrets = True

        mock_node = MagicMock()
        mock_node.id = 2

        mock_query = MagicMock()
        mock_query.filter.return_value.one_or_none.side_effect = [
            mock_assignment,
            mock_biome,
            mock_node,
        ]
        mock_db.query.return_value = mock_query

        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        assignment, biome, node = emitter._load_context(1)
        assert assignment is mock_assignment
        assert biome is mock_biome
        assert node is mock_node


class TestJoinerSecretEmitterResolveClusterId:
    """Test cluster ID resolution."""

    def test_resolve_cluster_id_from_constructor(self):
        """_resolve_cluster_id uses constructor override."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
            cluster_id="test-cluster",
        )

        mock_node = MagicMock()
        result = emitter._resolve_cluster_id(mock_node)
        assert result == "test-cluster"
        # Should not query DB
        mock_db.execute.assert_not_called()

    def test_resolve_cluster_id_from_storage_backend(self):
        """_resolve_cluster_id queries storage_backends when not set."""
        mock_db = MagicMock()
        mock_row = MagicMock()
        mock_row.__getitem__ = lambda self, i: "resolved-cluster" if i == 0 else None
        mock_db.execute.return_value.first.return_value = mock_row

        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        mock_node = MagicMock()
        mock_node.tenant_id = "tenant1"
        result = emitter._resolve_cluster_id(mock_node)
        assert result == "resolved-cluster"

    def test_resolve_cluster_id_storage_backend_missing(self):
        """_resolve_cluster_id raises when storage_backend query fails."""
        mock_db = MagicMock()
        mock_db.execute.return_value.first.return_value = None

        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        mock_node = MagicMock()
        mock_node.id = 1
        mock_node.tenant_id = "tenant1"

        with pytest.raises(EmitterStateError, match="cluster_id not resolvable"):
            emitter._resolve_cluster_id(mock_node)


class TestJoinerSecretEmitterDeriveLxdInstance:
    """Test LXD instance name derivation."""

    def test_derive_lxd_instance_host_workload(self):
        """_derive_lxd_instance uses node.name for host workloads."""
        mock_node = MagicMock()
        mock_node.name = "node-1"

        mock_biome = MagicMock()
        mock_biome.workload_type = "host"

        mock_assignment = MagicMock()

        result = JoinerSecretEmitter._derive_lxd_instance(
            mock_node, mock_biome, mock_assignment
        )
        assert result == "node-1"

    def test_derive_lxd_instance_lxd_workload(self):
        """_derive_lxd_instance uses biome kind and assignment ID."""
        mock_node = MagicMock()
        mock_biome = MagicMock()
        mock_biome.biome_kind = "ubuntu"
        mock_biome.workload_type = "lxd"

        mock_assignment = MagicMock()
        mock_assignment.id = 42

        result = JoinerSecretEmitter._derive_lxd_instance(
            mock_node, mock_biome, mock_assignment
        )
        assert result == "ubuntu-42"


class TestJoinerSecretEmitterValidateSpec:
    """Test joiner_emit_spec validation."""

    def test_validate_spec_missing(self):
        """_validate_spec returns empty list when spec is None."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        mock_biome = MagicMock()
        mock_biome.joiner_emit_spec = None

        result = emitter._validate_spec(mock_biome)
        assert result == []

    def test_validate_spec_not_dict(self):
        """_validate_spec raises when spec is not dict."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        mock_biome = MagicMock()
        mock_biome.id = 1
        mock_biome.joiner_emit_spec = "invalid"

        with pytest.raises(ExtractorSpecError, match="must be an object"):
            emitter._validate_spec(mock_biome)

    def test_validate_spec_extractors_not_list(self):
        """_validate_spec raises when extractors is not list."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        mock_biome = MagicMock()
        mock_biome.id = 1
        mock_biome.joiner_emit_spec = {"extractors": "not_a_list"}

        with pytest.raises(ExtractorSpecError, match="must be a list"):
            emitter._validate_spec(mock_biome)

    def test_validate_spec_extractor_not_dict(self):
        """_validate_spec raises when extractor entry not dict."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        mock_biome = MagicMock()
        mock_biome.id = 1
        mock_biome.joiner_emit_spec = {"extractors": ["not_a_dict"]}

        with pytest.raises(ExtractorSpecError, match="must be an object"):
            emitter._validate_spec(mock_biome)

    def test_validate_spec_invalid_source(self):
        """_validate_spec raises on invalid source."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        mock_biome = MagicMock()
        mock_biome.id = 1
        mock_biome.joiner_emit_spec = {
            "extractors": [
                {
                    "name": "test",
                    "source": "invalid_source",
                }
            ]
        }

        with pytest.raises(ExtractorSpecError, match="unsupported source"):
            emitter._validate_spec(mock_biome)

    def test_validate_spec_invalid_scope(self):
        """_validate_spec raises on invalid scope."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        mock_biome = MagicMock()
        mock_biome.id = 1
        mock_biome.joiner_emit_spec = {
            "extractors": [
                {
                    "name": "test",
                    "source": "exec",
                    "command": ["test"],
                    "scope": "invalid_scope",
                }
            ]
        }

        with pytest.raises(ExtractorSpecError, match="unsupported scope"):
            emitter._validate_spec(mock_biome)

    def test_validate_spec_negative_ttl(self):
        """_validate_spec raises on negative ttl_seconds."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        mock_biome = MagicMock()
        mock_biome.id = 1
        mock_biome.joiner_emit_spec = {
            "extractors": [
                {
                    "name": "test",
                    "source": "exec",
                    "command": ["test"],
                    "ttl_seconds": -1,
                }
            ]
        }

        with pytest.raises(ExtractorSpecError, match="ttl_seconds must be >= 0"):
            emitter._validate_spec(mock_biome)

    def test_validate_spec_success(self):
        """_validate_spec returns validated extractors."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        mock_biome = MagicMock()
        mock_biome.id = 1
        mock_biome.joiner_emit_spec = {
            "extractors": [
                {
                    "name": "test_exec",
                    "source": "exec",
                    "command": ["echo", "hello"],
                    "scope": "cluster",
                    "ttl_seconds": 3600,
                }
            ]
        }

        result = emitter._validate_spec(mock_biome)
        assert len(result) == 1
        assert result[0].name == "test_exec"
        assert result[0].source == "exec"


class TestJoinerSecretEmitterExtractSecret:
    """Test secret extraction via control tunnel."""

    def test_extract_secret_missing_command(self):
        """_extract_secret raises when exec source missing command."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        from app.workers.joiner_secret_emitter import _ExtractorSpec

        spec = _ExtractorSpec(
            name="test",
            source="exec",
            # Missing command
        )

        with pytest.raises(ExtractorSpecError, match="requires command"):
            emitter._extract_secret(1, "instance", spec)

    def test_extract_secret_missing_path(self):
        """_extract_secret raises when file source missing path."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        from app.workers.joiner_secret_emitter import _ExtractorSpec

        spec = _ExtractorSpec(
            name="test",
            source="file",
            # Missing path
        )

        with pytest.raises(ExtractorSpecError, match="requires path"):
            emitter._extract_secret(1, "instance", spec)

    def test_extract_secret_missing_url(self):
        """_extract_secret raises when http source missing url."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        from app.workers.joiner_secret_emitter import _ExtractorSpec

        spec = _ExtractorSpec(
            name="test",
            source="http_api",
            # Missing url
        )

        with pytest.raises(ExtractorSpecError, match="requires url"):
            emitter._extract_secret(1, "instance", spec)

    def test_extract_secret_missing_config_key(self):
        """_extract_secret raises when lxd source missing config_key."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        from app.workers.joiner_secret_emitter import _ExtractorSpec

        spec = _ExtractorSpec(
            name="test",
            source="lxd_config",
            # Missing config_key
        )

        with pytest.raises(ExtractorSpecError, match="requires config_key"):
            emitter._extract_secret(1, "instance", spec)

    def test_extract_secret_unsupported_source(self):
        """_extract_secret raises on unsupported source."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
        )

        from app.workers.joiner_secret_emitter import _ExtractorSpec

        spec = _ExtractorSpec(
            name="test",
            source="unsupported",
        )

        with pytest.raises(ExtractorSpecError, match="unsupported source"):
            emitter._extract_secret(1, "instance", spec)

    def test_extract_secret_tunnel_failure(self):
        """_extract_secret raises ControlTunnelExtractionError on tunnel failure."""
        mock_tunnel = MagicMock()
        mock_tunnel.run_command.side_effect = Exception("Tunnel error")

        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=mock_tunnel,
        )

        from app.workers.joiner_secret_emitter import _ExtractorSpec

        spec = _ExtractorSpec(
            name="test",
            source="exec",
            command=["echo", "test"],
        )

        with pytest.raises(ControlTunnelExtractionError):
            emitter._extract_secret(1, "instance", spec)

    def test_extract_secret_non_bytes_output(self):
        """_extract_secret raises when output is not bytes."""
        mock_tunnel = MagicMock()
        mock_tunnel.run_command.return_value = "not bytes"  # Invalid

        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=mock_tunnel,
        )

        from app.workers.joiner_secret_emitter import _ExtractorSpec

        spec = _ExtractorSpec(
            name="test",
            source="exec",
            command=["echo", "test"],
        )

        with pytest.raises(ControlTunnelExtractionError, match="non-bytes"):
            emitter._extract_secret(1, "instance", spec)


class TestJoinerSecretEmitterPublishEvent:
    """Test NATS event publishing."""

    def test_publish_emitted_event_no_nats(self):
        """_publish_emitted_event returns early when no NATS client."""
        mock_db = MagicMock()
        emitter = JoinerSecretEmitter(
            db_session=mock_db,
            vault_client=MagicMock(),
            control_tunnel_client=MagicMock(),
            nats_client=None,
        )

        # Should not raise
        emitter._publish_emitted_event(
            cluster_id="cluster1",
            joiner_secret_id="secret1",
            biome_kind="ubuntu",
            extractor_name="test",
            scope="cluster",
        )

