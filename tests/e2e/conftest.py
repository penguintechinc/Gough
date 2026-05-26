"""Pytest fixtures for E2E tests."""

import os
import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Generator, Dict, Any
import pytest
import requests
from datetime import datetime, timedelta


@pytest.fixture(scope="session")
def primary_cluster() -> Generator[Dict[str, Any], None, None]:
    """
    Bootstrap a primary Gough cluster in LXD for E2E tests.

    Yields:
        Dict with cluster config: api_url, admin_token, cluster_id, etc.
    """
    print("[primary_cluster] Bootstrapping primary cluster...")

    # Use gough init via subprocess (assumes `gough` CLI available in PATH)
    cluster_id = f"e2e-{datetime.now().strftime('%s')}"
    temp_dir = tempfile.mkdtemp(prefix=f"gough-primary-{cluster_id}-")

    # Mock bootstrap config (in CI, this would be driven by GitHub Actions env setup)
    config = {
        "cluster_id": cluster_id,
        "api_url": "http://localhost:8080",
        "admin_token": "test-token-" + os.urandom(16).hex(),
        "cluster_config_dir": temp_dir,
        "vault_unseal_keys": [],  # Would be seeded from gough init output
        "primary_ip": "127.0.0.1"
    }

    # Execute: gough init --cluster-id {id} --output-dir {dir}
    # For now, this is a placeholder; real implementation depends on gough CLI availability
    print(f"[primary_cluster] Using temporary directory: {temp_dir}")
    print(f"[primary_cluster] Cluster ID: {cluster_id}")

    # Wait for cluster to be ready (polling api-manager /health)
    max_retries = 60
    for i in range(max_retries):
        try:
            resp = requests.get(f"{config['api_url']}/health", timeout=2)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "healthy":
                    print("[primary_cluster] Cluster is healthy")
                    break
        except requests.RequestException:
            pass

        if i == max_retries - 1:
            raise TimeoutError(f"Primary cluster did not become healthy within {max_retries}s")

        time.sleep(1)

    yield config

    # Cleanup (tear down LXD instance, clear Vault, etc.)
    print(f"[primary_cluster] Tearing down cluster {cluster_id}")
    # subprocess.run(["lxc", "delete", "-f", cluster_id], capture_output=True)
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def sim_node_factory(primary_cluster) -> Generator:
    """
    Factory fixture that spins up a node-sim QEMU VM with given params.

    Returns:
        Callable that accepts kwargs: firmware, ipv6, secure_boot, dmi_uuid, smart_pattern, with_bmc
    """
    sim_nodes = []

    def _launch_sim(**kwargs) -> Dict[str, Any]:
        """Launch a node-sim and return its metadata."""
        script_dir = Path(__file__).parent.parent.parent / "dev-tools" / "node-sim"
        launch_script = script_dir / "launch-sim.sh"

        cmd = [str(launch_script)]

        # Build command from kwargs
        if "firmware" in kwargs:
            cmd.extend(["--firmware", kwargs["firmware"]])
        if "ipv6" in kwargs:
            cmd.extend(["--ipv6", kwargs["ipv6"]])
        if kwargs.get("secure_boot"):
            cmd.append("--secure-boot")
        if "dmi_uuid" in kwargs:
            cmd.extend(["--dmi-uuid", kwargs["dmi_uuid"]])
        if "smart_pattern" in kwargs:
            cmd.extend(["--smart-pattern", kwargs["smart_pattern"]])
        if kwargs.get("with_bmc"):
            cmd.append("--with-bmc")

        # Execute launch-sim.sh
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            raise RuntimeError(f"Failed to launch sim: {result.stderr}")

        # Parse output for PID file and other metadata
        # Expected output: "[launch-sim] QEMU PID: <pid>" etc.
        pid = None
        for line in result.stdout.split("\n"):
            if "QEMU PID:" in line:
                pid = int(line.split(":")[-1].strip())
                break

        if not pid:
            raise RuntimeError("Could not parse QEMU PID from launch-sim output")

        metadata = {
            "pid": pid,
            "dmi_uuid": kwargs.get("dmi_uuid", ""),
            "firmware": kwargs.get("firmware", "bios"),
            "ipv6_mode": kwargs.get("ipv6", "disabled"),
            "smart_pattern": kwargs.get("smart_pattern", "healthy"),
            "with_bmc": kwargs.get("with_bmc", False),
            "startup_time": time.time()
        }

        sim_nodes.append(metadata)
        return metadata

    yield _launch_sim

    # Cleanup
    print("[sim_node_factory] Cleaning up sim nodes...")
    cleanup_script = Path(__file__).parent.parent.parent / "dev-tools" / "node-sim" / "cleanup.sh"
    subprocess.run([str(cleanup_script)], capture_output=True)


@pytest.fixture
def gough_cli_token(primary_cluster) -> str:
    """
    Provide an authenticated CLI token for API calls.

    In CI, this would use OIDC mock to issue a real JWT.
    For local testing, returns a pre-shared admin token.
    """
    return primary_cluster["admin_token"]


@pytest.fixture
def api_client(primary_cluster, gough_cli_token):
    """
    HTTP client pre-configured with auth headers for API calls.
    """
    class GoughAPIClient:
        def __init__(self, base_url: str, token: str):
            self.base_url = base_url.rstrip("/")
            self.token = token
            self.session = requests.Session()
            self.session.headers.update({
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            })

        def get(self, path: str, **kwargs) -> requests.Response:
            return self.session.get(f"{self.base_url}{path}", **kwargs)

        def post(self, path: str, data: Dict = None, **kwargs) -> requests.Response:
            return self.session.post(f"{self.base_url}{path}", json=data, **kwargs)

        def put(self, path: str, data: Dict = None, **kwargs) -> requests.Response:
            return self.session.put(f"{self.base_url}{path}", json=data, **kwargs)

        def delete(self, path: str, **kwargs) -> requests.Response:
            return self.session.delete(f"{self.base_url}{path}", **kwargs)

    return GoughAPIClient(primary_cluster["api_url"], gough_cli_token)
