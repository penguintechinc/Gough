"""Seeds the four built-in biomes if they don't already exist.

This module provides idempotent seeding of the standard Gough built-in biomes:
- k8s-primary: Infrastructure biome for Kubernetes primary control plane
- k8s-worker: Infrastructure biome for Kubernetes worker nodes
- nest-agent: Infrastructure agent for cluster observability
- longhorn-agent: Application agent for distributed storage

All built-in biomes are pre-marked as signature_verified=True since they are
shipped with the product and validated at build time.
"""

from __future__ import annotations


BUILTIN_BIOMES = [
    {
        "name": "k8s-primary",
        "biome_kind": "infrastructure",
        "phase": "post_deploy",
        "lock_to_host": True,
        "emits_joiner_secrets": True,
        "default_frontend": {
            "mode": "kube-vip",
            "kube_vip_image_digest": "sha256:840305b94ef2a89abb3b7fd2b09edfbde690d90052020da4dff90679fe892da2",
            "kube_vip_version": "v0.8.8",
        },
    },
    {
        "name": "k8s-worker",
        "biome_kind": "infrastructure",
        "phase": "post_deploy",
        "lock_to_host": False,
        "emits_joiner_secrets": False,
    },
    {
        "name": "nest-agent",
        "biome_kind": "infrastructure",
        "phase": "always_on",
        "lock_to_host": False,
        "emits_joiner_secrets": False,
    },
    {
        "name": "longhorn-agent",
        "biome_kind": "application",
        "phase": "always_on",
        "lock_to_host": False,
        "emits_joiner_secrets": False,
    },
]


def seed_builtin_biomes(db: object) -> None:
    """Insert built-in biomes that don't exist yet. Idempotent.

    Args:
        db: PyDAL database instance (penguin-dal DAL object).

    Each biome is inserted with signature_verified=True and published_at set
    to indicate they are pre-validated product components.
    """
    from datetime import datetime, timezone

    for spec in BUILTIN_BIOMES:
        # Check if biome already exists by name
        existing = db(db.biomes.name == spec["name"]).select().first()
        if not existing:
            db.biomes.insert(
                name=spec["name"],
                biome_kind=spec["biome_kind"],
                phase=spec["phase"],
                lock_to_host=spec["lock_to_host"],
                emits_joiner_secrets=spec["emits_joiner_secrets"],
                signature_verified=True,
                published_at=datetime.now(timezone.utc),
            )
    db.commit()
