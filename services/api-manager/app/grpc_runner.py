"""gRPC server runner for Plan 2 (Deployment).

Starts a grpc.aio server on port 50051 alongside the Quart application.
Registered as a background asyncio task via app.before_serving in __init__.py.

# TODO(plan-4): Replace add_insecure_port with mTLS credentials via SPIFFE/SPIRE SVIDs.
"""

from __future__ import annotations

import logging
import os
import sys

# The protoc-generated *_pb2_grpc.py files use bare `from gough import …`.
# Adding app/grpc to sys.path makes the `gough` package importable by that name.
_GRPC_PKG_DIR = os.path.join(os.path.dirname(__file__), "grpc")
if _GRPC_PKG_DIR not in sys.path:
    sys.path.insert(0, _GRPC_PKG_DIR)

import grpc
from grpc import aio
from gough import ipxe_pb2_grpc, joiner_pb2_grpc, biomes_pb2_grpc, audit_pb2_grpc, identity_pb2_grpc
from app.grpc_server import IPXEServicer, JoinerSecretsServicer, BiomesServicer, AuditServicer, IdentityServicer

log = logging.getLogger(__name__)

_GRPC_PORT = 50051


async def serve(port: int = _GRPC_PORT) -> None:
    """Start and run the gRPC server until termination signal.

    Designed to run as an asyncio background task alongside Quart/hypercorn.
    """
    server = aio.server()

    ipxe_pb2_grpc.add_IPXEServicer_to_server(IPXEServicer(), server)
    joiner_pb2_grpc.add_JoinerSecretsServicer_to_server(JoinerSecretsServicer(), server)
    biomes_pb2_grpc.add_BiomesServicer_to_server(BiomesServicer(), server)
    audit_pb2_grpc.add_AuditServicer_to_server(AuditServicer(), server)
    identity_pb2_grpc.add_IdentityServicer_to_server(IdentityServicer(), server)

    # Plan-4: Load mTLS credentials from environment
    grpc_tls_cert_pem = os.getenv("GRPC_TLS_CERT_PEM")
    grpc_tls_key_pem = os.getenv("GRPC_TLS_KEY_PEM")

    if grpc_tls_cert_pem and grpc_tls_key_pem:
        try:
            cert_bytes = grpc_tls_cert_pem.encode() if isinstance(grpc_tls_cert_pem, str) else grpc_tls_cert_pem
            key_bytes = grpc_tls_key_pem.encode() if isinstance(grpc_tls_key_pem, str) else grpc_tls_key_pem
            credentials = grpc.ssl_server_credentials([(key_bytes, cert_bytes)])
            bound_port = server.add_secure_port(f"[::]:{port}", credentials)
            log.info("gRPC server started with mTLS on port %d (bound=%d)", port, bound_port)
        except Exception as e:
            log.warning("Failed to load mTLS credentials: %s; falling back to insecure port", e)
            bound_port = server.add_insecure_port(f"[::]:{port}")
            log.info("gRPC server started (insecure fallback) on port %d (bound=%d)", port, bound_port)
    else:
        bound_port = server.add_insecure_port(f"[::]:{port}")
        log.warning("gRPC mTLS not configured (GRPC_TLS_CERT_PEM/GRPC_TLS_KEY_PEM missing); running insecure")
        log.info("gRPC server started on port %d (bound=%d)", port, bound_port)

    await server.start()
    await server.wait_for_termination()
