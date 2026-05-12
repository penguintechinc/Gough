"""Prometheus metrics client for Gough capacity snapshots.

Provides current cluster and per-node resource usage snapshots. Used by the
CapacityPredictor to synthesize fallback forecasts when WaddleAI is degraded
or unavailable.

Metrics:
  * CPU: ``node_cpu_seconds_total`` (gauge, aggregated to %).
  * RAM: ``node_memory_MemAvailable_bytes`` and ``node_memory_MemTotal_bytes``.
  * Disk: ``node_filesystem_avail_bytes`` and ``node_filesystem_size_bytes``
    (aggregated across mounts).
  * Network: ``node_network_receive_bytes_total`` (aggregated to bps).
"""

from __future__ import annotations

import logging
from typing import Optional, Sequence

import httpx

from ..workers.capacity_predictor import (
    ClusterUsageSnapshot,
    NodeUsageSnapshot,
    PrometheusClientProtocol,
)

log = logging.getLogger(__name__)


class PrometheusClient(PrometheusClientProtocol):
    """Minimal Prometheus client for Gough capacity snapshots.

    Scope: Provide current resource usage snapshots (CPU, RAM, disk, network)
    for the cluster and per-node. Used exclusively by CapacityPredictor to
    synthesize fallback forecasts when WaddleAI is unavailable.

    Parameters
    ----------
    endpoint:
        Base URL for Prometheus (e.g., "http://prometheus:9090").
    timeout:
        Request timeout in seconds. Defaults to 10s.
    """

    def __init__(
        self,
        endpoint: str,
        timeout: float = 10.0,
    ) -> None:
        if not endpoint:
            raise ValueError("endpoint must be a non-empty URL")
        self._endpoint = endpoint.rstrip("/")
        self._timeout = timeout

    async def snapshot_node_usage(
        self, node_ids: Optional[Sequence[int]] = None
    ) -> list[NodeUsageSnapshot]:
        """Return current per-node CPU/RAM/disk/net usage.

        Returns an empty list on any Prometheus connectivity issue — the
        fallback forecast still succeeds with all-zeros snapshots.

        Parameters
        ----------
        node_ids:
            Optional filter. If provided, only return snapshots for these
            node IDs. If empty or None, return snapshots for all nodes.
        """
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                # Fetch CPU usage (100 - idle percentage)
                cpu_query = (
                    '100 - (avg by (instance) '
                    '(irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)'
                )
                cpu_resp = await client.get(
                    f"{self._endpoint}/api/v1/query",
                    params={"query": cpu_query},
                )
                cpu_data = self._parse_query_response(cpu_resp)

                # Fetch RAM usage
                ram_query = (
                    '(1 - (node_memory_MemAvailable_bytes / '
                    'node_memory_MemTotal_bytes)) * 100'
                )
                ram_resp = await client.get(
                    f"{self._endpoint}/api/v1/query",
                    params={"query": ram_query},
                )
                ram_data = self._parse_query_response(ram_resp)

                # Fetch Disk usage
                disk_query = (
                    '100 - ((node_filesystem_avail_bytes{mountpoint="/"} / '
                    'node_filesystem_size_bytes{mountpoint="/"}) * 100)'
                )
                disk_resp = await client.get(
                    f"{self._endpoint}/api/v1/query",
                    params={"query": disk_query},
                )
                disk_data = self._parse_query_response(disk_resp)

                # Fetch Network usage (receive bytes/sec)
                net_query = (
                    'irate(node_network_receive_bytes_total[5m])'
                )
                net_resp = await client.get(
                    f"{self._endpoint}/api/v1/query",
                    params={"query": net_query},
                )
                net_data = self._parse_query_response(net_resp)

            # Merge results by instance and convert to NodeUsageSnapshot list
            snapshots: list[NodeUsageSnapshot] = []
            instances = set()
            for result in cpu_data.values():
                instances.add(result["instance"])

            for instance in sorted(instances):
                try:
                    node_id = int(instance.split(":")[-1])
                except (ValueError, IndexError):
                    continue

                if node_ids and node_id not in node_ids:
                    continue

                snapshots.append(
                    NodeUsageSnapshot(
                        node_id=node_id,
                        cpu_used_pct=float(
                            cpu_data.get(instance, {}).get("value", 0.0)
                        ),
                        ram_used_pct=float(
                            ram_data.get(instance, {}).get("value", 0.0)
                        ),
                        disk_used_pct=float(
                            disk_data.get(instance, {}).get("value", 0.0)
                        ),
                        net_used_bps=float(
                            net_data.get(instance, {}).get("value", 0.0)
                        ),
                    )
                )

            return snapshots
        except Exception as exc:
            log.warning("Prometheus snapshot_node_usage failed: %s", exc)
            return []

    async def snapshot_cluster_usage(self) -> ClusterUsageSnapshot:
        """Return current cluster-aggregate CPU/RAM/disk usage.

        Returns zeros on any Prometheus connectivity issue — fallback
        forecast still succeeds with a conservative estimate.
        """
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                # Cluster-wide CPU (no by clause)
                cpu_query = (
                    '100 - (avg(irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)'
                )
                cpu_resp = await client.get(
                    f"{self._endpoint}/api/v1/query",
                    params={"query": cpu_query},
                )
                cpu_value = self._extract_scalar(cpu_resp)

                # Cluster-wide RAM
                ram_query = (
                    '(1 - (sum(node_memory_MemAvailable_bytes) / '
                    'sum(node_memory_MemTotal_bytes))) * 100'
                )
                ram_resp = await client.get(
                    f"{self._endpoint}/api/v1/query",
                    params={"query": ram_query},
                )
                ram_value = self._extract_scalar(ram_resp)

                # Cluster-wide Disk
                disk_query = (
                    '100 - ((sum(node_filesystem_avail_bytes{mountpoint="/"}) / '
                    'sum(node_filesystem_size_bytes{mountpoint="/"})) * 100)'
                )
                disk_resp = await client.get(
                    f"{self._endpoint}/api/v1/query",
                    params={"query": disk_query},
                )
                disk_value = self._extract_scalar(disk_resp)

                return ClusterUsageSnapshot(
                    cpu_used_pct=cpu_value,
                    ram_used_pct=ram_value,
                    disk_used_pct=disk_value,
                )
        except Exception as exc:
            log.warning("Prometheus snapshot_cluster_usage failed: %s", exc)
            return ClusterUsageSnapshot(
                cpu_used_pct=0.0,
                ram_used_pct=0.0,
                disk_used_pct=0.0,
            )


    def _parse_query_response(self, resp: httpx.Response) -> dict[str, dict]:
        """Parse Prometheus /api/v1/query response into {instance: {instance, value}}."""
        try:
            data = resp.json()
            if data.get("status") != "success":
                return {}
            results = data.get("data", {}).get("result", [])
            output = {}
            for result in results:
                metric = result.get("metric", {})
                instance = metric.get("instance", "unknown")
                value = float(result.get("value", [0, 0])[1]) if result.get("value") else 0.0
                output[instance] = {"instance": instance, "value": value}
            return output
        except Exception as exc:
            log.warning("Failed to parse Prometheus response: %s", exc)
            return {}

    def _extract_scalar(self, resp: httpx.Response) -> float:
        """Extract scalar value from Prometheus /api/v1/query response."""
        try:
            data = resp.json()
            if data.get("status") != "success":
                return 0.0
            result = data.get("data", {})
            if result.get("type") == "scalar":
                value = result.get("value", [0, 0])
                return float(value[1]) if value else 0.0
            return 0.0
        except Exception as exc:
            log.warning("Failed to extract scalar from Prometheus response: %s", exc)
            return 0.0


__all__ = ["PrometheusClient"]
