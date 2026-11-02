from engine.database_config import database_url_from_env


def test_preview_uses_only_its_preview_scoped_database_url():
    env = {
        "VERCEL_ENV": "preview",
        "PHISGUARD_PREVIEW_DATABASE_URL": "postgresql://preview/db",
        "DATABASE_URL": "postgresql://production/db",
        "DATABASE_POSTGRES_PRISMA_URL": "postgresql://shared/db",
    }

    assert database_url_from_env(env) == "postgresql://preview/db"


def test_preview_never_falls_back_to_generic_production_database_variables():
    env = {
        "VERCEL_ENV": "preview",
        "DATABASE_URL": "postgresql://production/db",
        "DATABASE_POSTGRES_PRISMA_URL": "postgresql://shared/db",
        "DATABASE_URL_UNPOOLED": "postgresql://unpooled/db",
    }

    assert database_url_from_env(env) == ""


def test_production_uses_the_existing_database_configuration():
    env = {
        "VERCEL_ENV": "production",
        "DATABASE_URL": "  postgresql://production/db  ",
        "PHISGUARD_PREVIEW_DATABASE_URL": "postgresql://preview/db",
    }

    assert database_url_from_env(env) == "postgresql://production/db"


def test_generic_database_precedence_is_unchanged_outside_preview():
    env = {
        "DATABASE_POSTGRES_PRISMA_URL": "postgresql://pooled/db",
        "DATABASE_URL_UNPOOLED": "postgresql://unpooled/db",
    }

    assert database_url_from_env(env) == "postgresql://pooled/db"
