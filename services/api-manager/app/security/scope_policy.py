"""Centralized OIDC scope policy for Gough API Manager."""

from __future__ import annotations

# ==============================================================================
# Known Scopes Catalog
# ==============================================================================

KNOWN_SCOPES: frozenset[str] = frozenset({
    # Read scopes (cluster, infrastructure introspection)
    "gough.cluster.read",
    "gough.nodes.read",
    "gough.disks.read",
    "gough.biomes.read",
    "gough.capacity.read",
    "gough.storage.read",
    "gough.audit.read",
    "gough.dr.read",
    "gough.bmc.read",
    "gough.joiner.read",

    # Write scopes (provisioning, configuration)
    "gough.nodes.provision",
    "gough.nodes.rekey",
    "gough.nodes.decommission",
    "gough.disks.plan",
    "gough.biomes.author",
    "gough.biomes.deploy",
    "gough.biomes.sign",
    "gough.storage.configure",
    "gough.migration.policy",
    "gough.migration.trigger",
    "gough.dr.drill",
    "gough.bmc.configure",
    "gough.joiner.rotate",

    # Admin and superadmin scopes (complete system control)
    "gough.cluster.admin",
    "gough.cluster.superadmin",

    # Dangerous override scopes (require explicit approval/MFA in Wave 2)
    "gough.dr.promote",
    "gough.biomes.unsafe-skip-signing",
    "gough.migration.override-lock",
})


# ==============================================================================
# Scope Policy: (HTTP Method, Path Pattern) -> Required Scopes Set
# ==============================================================================

SCOPE_POLICY: dict[tuple[str, str], frozenset[str] | None] = {
    # Biomes endpoints (existing in Sprint 1 M1)
    ("GET", "/api/v1/biomes"): frozenset({"gough.biomes.read"}),
    ("POST", "/api/v1/biomes"): frozenset({"gough.biomes.author"}),
    ("GET", "/api/v1/biomes/<int:biome_id>"): frozenset({"gough.biomes.read"}),
    ("PUT", "/api/v1/biomes/<int:biome_id>"): frozenset({"gough.biomes.author"}),
    ("DELETE", "/api/v1/biomes/<int:biome_id>"): frozenset({"gough.cluster.admin"}),
    ("POST", "/api/v1/biomes/<int:biome_id>/upload"): frozenset({"gough.biomes.author"}),
    ("POST", "/api/v1/biomes/<int:biome_id>/sign"): frozenset({"gough.biomes.sign"}),
    ("POST", "/api/v1/biomes/<int:biome_id>/upgrade"): frozenset({"gough.biomes.deploy"}),
    ("GET", "/api/v1/biomes/<int:biome_id>/eligibility"): frozenset({"gough.biomes.read"}),
    ("POST", "/api/v1/biomes/render-cloud-init"): frozenset({"gough.biomes.read"}),
    ("GET", "/api/v1/biomes/groups"): frozenset({"gough.biomes.read"}),
    ("POST", "/api/v1/biomes/groups"): frozenset({"gough.biomes.author"}),
    ("GET", "/api/v1/biomes/groups/<int:group_id>"): frozenset({"gough.biomes.read"}),
    ("PUT", "/api/v1/biomes/groups/<int:group_id>"): frozenset({"gough.biomes.author"}),
    ("DELETE", "/api/v1/biomes/groups/<int:group_id>"): frozenset({"gough.cluster.admin"}),

    # Nodes endpoints
    ("GET", "/api/v1/nodes"): frozenset({"gough.nodes.read"}),
    ("GET", "/api/v1/nodes/<int:node_id>"): frozenset({"gough.nodes.read"}),
    ("PATCH", "/api/v1/nodes/<int:node_id>"): frozenset({"gough.nodes.provision"}),
    ("POST", "/api/v1/nodes/<int:node_id>/deploy"): frozenset({"gough.nodes.provision"}),
    ("POST", "/api/v1/nodes/<int:node_id>/reject"): frozenset({"gough.nodes.provision"}),
    ("POST", "/api/v1/nodes/<int:node_id>/rekey"): frozenset({"gough.nodes.rekey"}),
    ("POST", "/api/v1/nodes/<int:node_id>/evacuate"): frozenset({"gough.nodes.provision"}),
    ("DELETE", "/api/v1/nodes/<int:node_id>"): frozenset({"gough.nodes.decommission"}),
    ("POST", "/api/v1/nodes/<int:node_id>/events"): frozenset(),
    ("GET", "/api/v1/nodes/<int:node_id>/tags"): frozenset({"gough.nodes.read"}),
    ("PATCH", "/api/v1/nodes/<int:node_id>/tags"): frozenset({"gough.nodes.provision"}),
    ("POST", "/api/v1/nodes/manual"): frozenset({"gough.nodes.provision", "gough.cluster.admin"}),
    ("POST", "/api/v1/nodes/discover"): frozenset(),
    ("POST", "/api/v1/nodes/<int:node_id>/biomes"): frozenset({"gough.biomes.deploy"}),
    ("GET", "/api/v1/nodes/<int:node_id>/biomes"): frozenset({"gough.biomes.read"}),
    ("DELETE", "/api/v1/nodes/<int:node_id>/biomes/<int:biome_id>"): frozenset({"gough.biomes.deploy"}),

    # Disks endpoints
    ("GET", "/api/v1/nodes/<int:node_id>/disks"): frozenset({"gough.disks.read"}),
    ("POST", "/api/v1/nodes/<int:node_id>/disks/<int:disk_id>/plan"): frozenset({"gough.disks.plan"}),
    ("PATCH", "/api/v1/nodes/<int:node_id>/disks/<int:disk_id>"): frozenset({"gough.disks.plan"}),
    ("POST", "/api/v1/nodes/<int:node_id>/disks/<int:disk_id>/smart-recheck"): frozenset({"gough.disks.plan"}),

    # Migration endpoints
    ("GET", "/api/v1/migration/policy"): frozenset({"gough.capacity.read"}),
    ("PATCH", "/api/v1/migration/policy"): frozenset({"gough.migration.policy"}),
    ("POST", "/api/v1/migration/biome/<int:instance_id>"): frozenset({"gough.migration.trigger"}),
    ("GET", "/api/v1/migration/events"): frozenset({"gough.capacity.read"}),
    ("GET", "/api/v1/migration/safety-envelope"): frozenset({"gough.capacity.read"}),

    # Capacity endpoints
    ("GET", "/api/v1/capacity/forecast"): frozenset({"gough.capacity.read"}),
    ("GET", "/api/v1/capacity/risks"): frozenset({"gough.capacity.read"}),

    # Audit endpoints
    ("GET", "/api/v1/audit/events"): frozenset({"gough.audit.read"}),
    ("POST", "/api/v1/audit/verify"): frozenset({"gough.audit.read"}),
    ("GET", "/api/v1/audit/export"): frozenset({"gough.cluster.superadmin"}),

    # Joiner secrets endpoints
    ("GET", "/api/v1/clusters/<uuid:cluster_id>/joiner-secrets"): frozenset({"gough.joiner.read"}),
    ("POST", "/api/v1/clusters/<uuid:cluster_id>/joiner-secrets/<uuid:js_id>/rotate"): frozenset({"gough.joiner.rotate"}),
    ("DELETE", "/api/v1/clusters/<uuid:cluster_id>/joiner-secrets/<uuid:js_id>"): frozenset({"gough.cluster.admin"}),

    # Cluster storage endpoints
    ("GET", "/api/v1/clusters/<uuid:cluster_id>/storage"): frozenset({"gough.storage.read"}),
    ("PATCH", "/api/v1/clusters/<uuid:cluster_id>/storage"): frozenset({"gough.storage.configure"}),
    ("POST", "/api/v1/clusters/<uuid:cluster_id>/storage/switch-primary"): frozenset({"gough.cluster.admin"}),

    # Cluster LXD endpoints
    ("GET", "/api/v1/clusters/<uuid:cluster_id>/lxd/members"): frozenset({"gough.cluster.read"}),
    ("POST", "/api/v1/clusters/<uuid:cluster_id>/lxd/join"): frozenset({"gough.cluster.admin"}),

    # Cluster network endpoints
    ("GET", "/api/v1/clusters/<uuid:cluster_id>/network-pools"): frozenset({"gough.cluster.read"}),
    ("PATCH", "/api/v1/clusters/<uuid:cluster_id>/network-pools"): frozenset({"gough.cluster.admin"}),

    # Cluster identity plane endpoints
    ("GET", "/api/v1/clusters/<uuid:cluster_id>/identity-plane"): frozenset({"gough.cluster.read"}),
    ("PATCH", "/api/v1/clusters/<uuid:cluster_id>/identity-plane"): frozenset({"gough.cluster.admin"}),

    # Cluster adoption and config endpoints
    ("POST", "/api/v1/clusters/<uuid:cluster_id>/adopt"): frozenset({"gough.cluster.superadmin"}),
    ("GET", "/api/v1/clusters/<uuid:cluster_id>/config"): frozenset({"gough.cluster.read"}),
    ("PATCH", "/api/v1/clusters/<uuid:cluster_id>/config"): frozenset({"gough.cluster.admin"}),

    # Primary HA endpoints
    ("GET", "/api/v1/primary/status"): frozenset({"gough.cluster.read"}),
    ("POST", "/api/v1/primary/replace"): frozenset({"gough.cluster.admin"}),
    ("POST", "/api/v1/primary/force-recover"): frozenset({"gough.cluster.superadmin"}),

    # DR endpoints
    ("POST", "/api/v1/dr/drill"): frozenset({"gough.dr.drill"}),
    ("GET", "/api/v1/dr/drills"): frozenset({"gough.dr.read"}),
    ("POST", "/api/v1/dr/promote"): frozenset({"gough.dr.promote"}),

    # Webhooks endpoints
    ("GET", "/api/v1/webhooks"): frozenset({"gough.cluster.admin"}),
    ("POST", "/api/v1/webhooks"): frozenset({"gough.cluster.admin"}),
    ("DELETE", "/api/v1/webhooks/<int:webhook_id>"): frozenset({"gough.cluster.admin"}),
    ("POST", "/api/v1/webhooks/<int:webhook_id>/test"): frozenset({"gough.cluster.admin"}),
    ("GET", "/api/v1/webhooks/keys/<string:tenant>"): frozenset(),

    # Integrations endpoints
    ("GET", "/api/v1/integrations/status"): frozenset({"gough.cluster.read"}),
    ("POST", "/api/v1/integrations/<string:product>/configure"): frozenset({"gough.cluster.admin"}),
    ("POST", "/api/v1/integrations/<string:product>/rotate-credentials"): frozenset({"gough.cluster.admin"}),

    # iPXE endpoints
    ("POST", "/api/v1/ipxe/bind-mac"): frozenset({"gough.nodes.provision"}),
    ("POST", "/api/v1/ipxe/mint-bootstrap-token"): frozenset({"gough.nodes.provision"}),

    # Webhooks
    ("GET", "/api/v1/webhooks"): frozenset({"gough.cluster.admin"}),
    ("POST", "/api/v1/webhooks"): frozenset({"gough.cluster.admin"}),
    ("DELETE", "/api/v1/webhooks/<string:webhook_id>"): frozenset({"gough.cluster.admin"}),
    ("POST", "/api/v1/webhooks/<string:webhook_id>/test"): frozenset({"gough.cluster.admin"}),
}


# ==============================================================================
# Anonymous Paths (No Authentication Required)
# ==============================================================================

ANONYMOUS_PATHS: frozenset[tuple[str, str]] = frozenset({
    ("GET", "/healthz"),
    ("GET", "/readyz"),
    ("GET", "/api/v1/version"),
    ("GET", "/api/v1/ipxe/helper/<string:mac>"),
    ("GET", "/api/v1/ipxe/deploy/<string:mac>"),
    ("GET", "/api/v1/ipxe/kernel/<string:name>"),
    ("GET", "/api/v1/ipxe/initrd/<string:name>"),
    ("GET", "/api/v1/ipxe/helper-efi/<string:mac>"),
})


# ==============================================================================
# Well-Formedness Validation (Load-Time Enforcement)
# ==============================================================================

def assert_policy_well_formed() -> None:
    """Validate scope policy at import time."""
    seen: set[tuple[str, str]] = set()
    for (method, path), scopes in SCOPE_POLICY.items():
        if (method, path) in seen:
            raise ValueError(f"Duplicate entry: ({method}, {path})")
        seen.add((method, path))
        if scopes is not None:
            unknown = scopes - KNOWN_SCOPES
            if unknown:
                raise ValueError(f"Unknown scopes at ({method}, {path})")

    policy_keys = set(SCOPE_POLICY.keys())
    for anon_path in ANONYMOUS_PATHS:
        if anon_path in policy_keys:
            raise ValueError(f"Anonymous path {anon_path} conflicts with policy")


# Enforce well-formedness at import time
assert_policy_well_formed()
