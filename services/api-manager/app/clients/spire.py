"""SPIRE client for workload identity and registration."""

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from time import sleep
from typing import Any

try:
    from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient
except ImportError:
    DefaultWorkloadApiClient = None  # type: ignore[assignment,misc]

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class SpireSvid(BaseModel):
    """SPIRE X.509 SVID (Subject Verb ID)."""

    spiffe_id: str = Field(..., description="SPIFFE identity URI")
    cert_pem: str = Field(..., description="X.509 certificate in PEM format")
    key_pem: str = Field(..., description="Private key in PEM format")
    expires_at: datetime = Field(..., description="Certificate expiration timestamp")


class SpireRegistrationEntry(BaseModel):
    """SPIRE registration entry for workload identity."""

    spiffe_id: str = Field(..., description="SPIFFE identity URI")
    parent_id: str = Field(..., description="Parent SPIFFE ID")
    selectors: dict[str, str] = Field(
        default_factory=dict, description="Workload selectors (type->value pairs)"
    )
    ttl_seconds: int = Field(default=3600, description="SVID TTL in seconds")


class SpireError(Exception):
    """Base SPIRE client error."""

    pass


class SpireWorkloadApiUnavailable(SpireError):
    """Workload API socket unavailable."""

    pass


class SpireSvidUnavailable(SpireError):
    """No SVID returned from agent."""

    pass


class SpireRegistrationFailed(SpireError):
    """Registration via SPIRE server failed."""

    pass


class SpireClient:
    """Client for SPIRE workload API and registration."""

    def __init__(
        self, workload_api_socket: str | None = None, server_address: str | None = None
    ) -> None:
        """Initialize SPIRE client.

        Args:
            workload_api_socket: Unix socket path for SPIRE agent (format: unix:///path/to/socket).
                Defaults to SPIRE_AGENT_SOCKET env var, then unix:///tmp/spire-agent/public/api.sock.
            server_address: SPIRE server gRPC address (host:port).
                Defaults to SPIRE_SERVER_ADDRESS env var, then localhost:8081.

        Raises:
            ValueError: If socket or server address invalid.
        """
        self.workload_api_socket = (
            workload_api_socket
            or os.getenv("SPIRE_AGENT_SOCKET", "unix:///tmp/spire-agent/public/api.sock")
        )
        self.server_address = (
            server_address or os.getenv("SPIRE_SERVER_ADDRESS", "localhost:8081")
        )

        if not self.workload_api_socket.startswith("unix://"):
            raise ValueError(
                f"Invalid workload_api_socket: {self.workload_api_socket}. "
                "Must start with 'unix://'"
            )
        if ":" not in self.server_address:
            raise ValueError(
                f"Invalid server_address: {self.server_address}. "
                "Must contain ':' separator (host:port)"
            )

        self._workload_api_client: DefaultWorkloadApiClient | None = None

    def _get_workload_api_client(self) -> DefaultWorkloadApiClient:
        """Lazily initialize and return workload API client."""
        if self._workload_api_client is None:
            self._workload_api_client = DefaultWorkloadApiClient(
                socket_path=self.workload_api_socket
            )
        return self._workload_api_client

    def fetch_x509_svid(self, audience: str | None = None) -> SpireSvid:
        """Fetch X.509 SVID from SPIRE agent.

        Args:
            audience: Optional audience (unused by pyspiffe; included for API compat).

        Returns:
            SpireSvid with certificate, key, and expiration.

        Raises:
            SpireWorkloadApiUnavailable: If agent socket unavailable.
            SpireSvidUnavailable: If no SVIDs returned.
        """
        try:
            client = self._get_workload_api_client()
            x509_context = client.fetch_x509_context()
        except Exception as e:
            logger.error(f"Workload API error: {e}")
            raise SpireWorkloadApiUnavailable(f"Failed to fetch X.509 context: {e}") from e

        if not x509_context or not x509_context.svid_list:
            raise SpireSvidUnavailable("No SVIDs returned from agent")

        svid = x509_context.svid_list[0]
        logger.info(f"Fetched X.509 SVID: {svid.spiffe_id}")

        return SpireSvid(
            spiffe_id=str(svid.spiffe_id),
            cert_pem=svid.cert.public_bytes_pem(),
            key_pem=svid.private_key.private_bytes_pem(),
            expires_at=svid.cert.expires_at.replace(tzinfo=timezone.utc),
        )

    def fetch_jwt_svid(self, audience: list[str]) -> str:
        """Fetch JWT SVID from SPIRE agent.

        Args:
            audience: List of audiences for the JWT.

        Returns:
            Signed JWT SVID token string.

        Raises:
            SpireWorkloadApiUnavailable: If agent socket unavailable.
            SpireSvidUnavailable: If no JWT returned.
        """
        try:
            client = self._get_workload_api_client()
            jwt_svid = client.fetch_jwt_svid(audiences=audience)
        except Exception as e:
            logger.error(f"JWT fetch error: {e}")
            raise SpireWorkloadApiUnavailable(f"Failed to fetch JWT SVID: {e}") from e

        if not jwt_svid or not jwt_svid.token:
            raise SpireSvidUnavailable("No JWT SVID returned from agent")

        logger.info(f"Fetched JWT SVID for audiences: {audience}")
        return jwt_svid.token

    def register_workload(self, entry: SpireRegistrationEntry) -> str:
        """Register a workload identity with SPIRE server.

        Uses subprocess to invoke spire-server entry create (upstream pattern).

        Args:
            entry: Registration entry with SPIFFE ID, parent, selectors, TTL.

        Returns:
            Registered entry ID.

        Raises:
            SpireRegistrationFailed: If registration failed.
        """
        cmd = [
            "spire-server",
            "entry",
            "create",
            "-spiffeID",
            entry.spiffe_id,
            "-parentID",
            entry.parent_id,
            "-ttl",
            str(entry.ttl_seconds),
            "-serverAddress",
            self.server_address,
        ]

        for sel_type, sel_val in entry.selectors.items():
            cmd.extend(["-selector", f"{sel_type}:{sel_val}"])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, check=False
            )
        except subprocess.TimeoutExpired as e:
            logger.error(f"spire-server timeout: {e}")
            raise SpireRegistrationFailed(f"Registration timeout: {e}") from e

        if result.returncode != 0:
            logger.error(f"spire-server stderr: {result.stderr}")
            raise SpireRegistrationFailed(
                f"spire-server entry create failed: {result.stderr}"
            )

        match = re.search(r"Entry ID\s*:\s*([a-f0-9\-]+)", result.stdout)
        if not match:
            logger.error(f"spire-server stdout: {result.stdout}")
            raise SpireRegistrationFailed("Could not parse entry ID from spire-server output")

        entry_id = match.group(1)
        logger.info(f"Registered workload entry: {entry_id}")
        return entry_id

    def list_registrations(self, parent_id: str | None = None) -> list[SpireRegistrationEntry]:
        """List registration entries, optionally filtered by parent.

        Uses subprocess to invoke spire-server entry show.

        Args:
            parent_id: Optional parent SPIFFE ID filter.

        Returns:
            List of SpireRegistrationEntry objects.

        Raises:
            SpireError: If listing failed.
        """
        cmd = [
            "spire-server",
            "entry",
            "show",
            "-serverAddress",
            self.server_address,
            "-output",
            "json",
        ]
        if parent_id:
            cmd.extend(["-parentID", parent_id])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, check=False
            )
        except subprocess.TimeoutExpired as e:
            logger.error(f"spire-server timeout: {e}")
            raise SpireError(f"List registrations timeout: {e}") from e

        if result.returncode != 0:
            logger.error(f"spire-server stderr: {result.stderr}")
            raise SpireError(f"spire-server entry show failed: {result.stderr}")

        try:
            data = json.loads(result.stdout) if result.stdout.strip() else {"entries": []}
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            raise SpireError(f"Failed to parse spire-server JSON output: {e}") from e

        entries = []
        for entry_data in data.get("entries", []):
            entry = SpireRegistrationEntry(
                spiffe_id=entry_data.get("spiffeID", ""),
                parent_id=entry_data.get("parentID", ""),
                selectors={
                    sel["type"]: sel["value"]
                    for sel in entry_data.get("selectors", [])
                },
                ttl_seconds=entry_data.get("ttl", 3600),
            )
            entries.append(entry)

        logger.info(f"Listed {len(entries)} registrations")
        return entries

    def wait_for_workload_api(self, timeout: int = 30) -> None:
        """Poll for workload API availability.

        Args:
            timeout: Max seconds to wait.

        Raises:
            SpireWorkloadApiUnavailable: If timeout reached.
        """
        elapsed = 0
        while elapsed < timeout:
            try:
                self.fetch_x509_svid()
                logger.info("Workload API ready")
                return
            except (SpireWorkloadApiUnavailable, SpireSvidUnavailable):
                elapsed += 1
                sleep(1)

        raise SpireWorkloadApiUnavailable(
            f"Workload API not ready after {timeout}s"
        )
