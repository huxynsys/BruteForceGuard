"""Phase 9.1 — centralized production configuration.

Covers environment/log-level validation, development defaults, explicitly
configured CORS origins, and the production guard rails (explicit origins,
no wildcard, PostgreSQL required, no create_all bootstrap).
"""

from __future__ import annotations

import logging

import pytest
from pydantic import ValidationError

from app.core.config import (
    DEVELOPMENT_CORS_ORIGINS,
    ConfigurationError,
    Settings,
)

DEV_DB = "sqlite+pysqlite:///:memory:"
PROD_DB = "postgresql+psycopg://bfg_user:secret@postgres:5432/bruteforceguard"


def _dev(**overrides) -> Settings:
    overrides.setdefault("database_url", DEV_DB)
    overrides.setdefault("app_env", "development")
    return Settings(**overrides)


def _prod(**overrides) -> Settings:
    overrides.setdefault("database_url", PROD_DB)
    overrides.setdefault("app_env", "production")
    overrides.setdefault("cors_allowed_origins", "https://bfg.example.com")
    return Settings(**overrides)


# ---------------------------------------------------------------------------
# Development behaviour is unchanged
# ---------------------------------------------------------------------------


def test_development_defaults_are_preserved():
    settings = _dev()

    assert settings.app_env == "development"
    assert settings.log_level == "INFO"
    assert settings.is_production is False
    assert settings.create_all_on_startup is False
    assert settings.docs_enabled is True
    assert settings.cors_origins == list(DEVELOPMENT_CORS_ORIGINS)
    assert settings.cors_allow_credentials is True
    assert settings.database_backend == "sqlite"


def test_configured_origins_are_used_and_trimmed():
    settings = _dev(
        cors_allowed_origins=" https://a.example.com , https://b.example.com ",
    )

    assert settings.cors_origins == [
        "https://a.example.com",
        "https://b.example.com",
    ]
    assert settings.cors_allow_credentials is True


def test_wildcard_origin_disables_credentials():
    settings = _dev(cors_allowed_origins="*")

    assert settings.cors_origins == ["*"]
    assert settings.cors_allow_credentials is False


def test_log_level_is_normalized_and_resolved():
    settings = _dev(log_level="debug")

    assert settings.log_level == "DEBUG"
    assert settings.log_level_value == logging.DEBUG


# ---------------------------------------------------------------------------
# Invalid configuration fails fast
# ---------------------------------------------------------------------------


def test_invalid_app_env_is_rejected():
    with pytest.raises(ValidationError) as excinfo:
        _dev(app_env="prod")

    assert "APP_ENV" in str(excinfo.value)


def test_invalid_log_level_is_rejected():
    with pytest.raises(ValidationError) as excinfo:
        _dev(log_level="verbose")

    assert "LOG_LEVEL" in str(excinfo.value)


def test_empty_database_url_is_rejected():
    with pytest.raises(ValidationError) as excinfo:
        _dev(database_url="   ")

    assert "DATABASE_URL" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Production guard rails
# ---------------------------------------------------------------------------


def test_production_requires_explicit_cors_origins():
    with pytest.raises(ValidationError) as excinfo:
        Settings(app_env="production", database_url=PROD_DB)

    assert "CORS_ALLOWED_ORIGINS" in str(excinfo.value)


def test_production_rejects_wildcard_origin():
    with pytest.raises(ValidationError) as excinfo:
        _prod(cors_allowed_origins="*")

    assert "wildcard" in str(excinfo.value).lower()


def test_production_rejects_non_postgresql_database():
    with pytest.raises(ValidationError) as excinfo:
        _prod(database_url=DEV_DB)

    assert "PostgreSQL" in str(excinfo.value)


def test_production_rejects_create_all_bootstrap():
    with pytest.raises(ValidationError) as excinfo:
        _prod(create_all_on_startup=True)

    assert "CREATE_ALL_ON_STARTUP" in str(excinfo.value)


def test_production_accepts_a_valid_configuration():
    settings = _prod()

    assert settings.is_production is True
    assert settings.docs_enabled is False
    assert settings.cors_origins == ["https://bfg.example.com"]
    assert settings.database_backend == "postgresql"


def test_cors_origins_property_guards_production_even_bypassing_validation():
    """Defensive check: an unvalidated production settings object still refuses."""

    unvalidated = Settings.model_construct(
        app_env="production",
        database_url=PROD_DB,
        cors_allowed_origins="",
    )

    with pytest.raises(ConfigurationError):
        _ = unvalidated.cors_origins
