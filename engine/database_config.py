"""Resolve the persistent database URL for the current deployment environment.

Preview deployments intentionally use a separate, Preview-only Neon connection.
They must never fall back to the shared Production database credentials.
"""
from __future__ import annotations

from collections.abc import Mapping


PREVIEW_DATABASE_URL_ENV = "PHISGUARD_PREVIEW_DATABASE_URL"


def database_url_from_env(environ: Mapping[str, str]) -> str:
    """Return the configured database URL without crossing deployment scopes."""
    if environ.get("VERCEL_ENV", "").strip().lower() == "preview":
        # Fail closed: don't use generic DATABASE_* values in Preview, since
        # those may point at the Production database.
        return environ.get(PREVIEW_DATABASE_URL_ENV, "").strip()

    return (
        environ.get("DATABASE_URL", "").strip()
        or environ.get("DATABASE_POSTGRES_PRISMA_URL", "").strip()
        or environ.get("DATABASE_URL_UNPOOLED", "").strip()
    )
