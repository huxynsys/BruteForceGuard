"""Centralized application configuration (Phase 9.1).

Every application setting is declared here once and read from the
environment / ``.env`` file through ``pydantic-settings``.  Phase 7's
security-intelligence tunables (``PRIVILEGED_USERS``, ``SERVICE_SENSITIVITY``,
``RISK_WEIGHTS``, ``RISK_LEVEL_BOUNDARIES``, ``REPUTATION_LEVEL_BOUNDARIES``)
are declared centrally too and consumed by ``app.intelligence.config``, so a
deployment is tunable entirely through environment variables.

Development defaults are unchanged, so local development and the existing
test suite behave exactly as before.  Production deployments must be explicit
about the settings that matter for safety — allowed CORS origins and a
PostgreSQL database URL — and invalid configuration fails fast with a clear
message instead of silently degrading.
"""

from __future__ import annotations

import logging

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

VALID_ENVIRONMENTS = ("development", "test", "staging", "production")

VALID_LOG_LEVELS = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET")

#: Origins allowed when ``CORS_ALLOWED_ORIGINS`` is unset outside production.
#: These are the Vite development-server origins used by the Phase 6/7
#: dashboard, so the development workflow continues to work unchanged.
DEVELOPMENT_CORS_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)

POSTGRESQL_DRIVERS = ("postgresql", "postgres")


class ConfigurationError(ValueError):
    """Raised when the environment configuration is invalid."""


class Settings(BaseSettings):
    """Application settings loaded from the environment / ``.env``."""

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Core ---------------------------------------------------------
    app_env: str = "development"
    database_url: str
    log_level: str = "INFO"

    # --- HTTP / CORS --------------------------------------------------
    # Comma-separated list of allowed browser origins.  Empty means "use the
    # development defaults" (outside production only).
    cors_allowed_origins: str = ""

    # --- IP management / admin actions ----------------------------------
    # Comma-separated API tokens accepted for IP blocklist/whitelist writes.
    # Empty means the feature is intentionally disabled until configured.
    ip_management_api_tokens: str = ""

    # --- Alert triage lifecycle ------------------------------------------
    # Comma-separated API tokens accepted for alert status transitions
    # (PATCH /api/v1/alerts/{id}), each bound to a role: "token=role" where
    # role is "analyst" or "admin".  A token without "=role" grants the
    # least-privileged "analyst" role (unknown roles fall back to analyst).
    # Empty means alert triage writes are intentionally disabled (503) until
    # configured - the same fail-closed posture as IP management.
    alert_triage_api_tokens: str = ""

    # --- Interactive authentication (login sessions + RBAC) ----------------
    # Lifetime of a login session in minutes.  Sessions are stored server-side
    # as SHA-256 token hashes with an explicit expiry and revocation timestamp
    # (logout, password change, deactivation and role change all revoke them).
    auth_session_ttl_minutes: int = 480

    # PBKDF2-HMAC-SHA256 iterations for password hashing.  The iteration count
    # is stored inside each hash, so raising this never invalidates existing
    # passwords.  Lowered automatically by the test suite for speed.
    auth_password_iterations: int = 600_000

    # First-run bootstrap administrator.  Created at startup when the password
    # is non-empty and the username does not exist yet; never overwritten
    # afterwards (rotate via PATCH /api/v1/users/{id}).  Empty = disabled.
    auth_bootstrap_admin_username: str = "admin"
    auth_bootstrap_admin_password: str = ""

    # Login brute-force guard: after this many failed attempts per
    # (client IP, username) inside the window, login answers 429.
    auth_login_max_failures: int = 5
    auth_login_window_seconds: int = 300

    # --- Legacy bootstrap (development / tests only) -------------------
    # Alembic is the authoritative schema mechanism (Phase 9.2).  This flag
    # exists so legacy `create_all` workflows can still be bootstrapped
    # explicitly; it is rejected in production.
    create_all_on_startup: bool = False

    # --- Phase 7 security-intelligence tunables -----------------------
    # Declared centrally; validated by `app.intelligence.config`.
    privileged_users: str = ""
    service_sensitivity: str = ""
    risk_weights: str = ""
    risk_level_boundaries: str = ""
    reputation_level_boundaries: str = ""

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    @field_validator("app_env")
    @classmethod
    def _validate_app_env(cls, value: str) -> str:
        normalized = (value or "").strip().lower()
        if normalized not in VALID_ENVIRONMENTS:
            raise ConfigurationError(
                "APP_ENV must be one of "
                f"{', '.join(VALID_ENVIRONMENTS)}; got {value!r}"
            )
        return normalized

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        normalized = (value or "").strip().upper()
        if normalized not in VALID_LOG_LEVELS:
            raise ConfigurationError(
                "LOG_LEVEL must be one of "
                f"{', '.join(VALID_LOG_LEVELS)}; got {value!r}"
            )
        return normalized

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, value: str) -> str:
        if not (value or "").strip():
            raise ConfigurationError("DATABASE_URL must not be empty")
        return value.strip()

    @model_validator(mode="after")
    def _validate_production(self) -> "Settings":
        """Reject configuration that would be unsafe in production."""
        if not self.is_production:
            return self

        if not self.cors_allowed_origins.strip():
            raise ConfigurationError(
                "CORS_ALLOWED_ORIGINS must be set explicitly when "
                "APP_ENV=production (development defaults are not allowed)"
            )
        if "*" in self.cors_origins:
            raise ConfigurationError(
                "CORS_ALLOWED_ORIGINS must not contain the '*' wildcard "
                "when APP_ENV=production"
            )
        if self.database_backend not in POSTGRESQL_DRIVERS:
            raise ConfigurationError(
                "DATABASE_URL must point at PostgreSQL when "
                f"APP_ENV=production; got {self.database_backend!r}"
            )
        if self.create_all_on_startup:
            raise ConfigurationError(
                "CREATE_ALL_ON_STARTUP must be disabled when "
                "APP_ENV=production; use Alembic migrations"
            )
        return self

    # ------------------------------------------------------------------
    # Derived values
    # ------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def cors_origins(self) -> list[str]:
        """Allowed browser origins for the current environment."""
        if self.cors_allowed_origins.strip():
            return [
                origin.strip()
                for origin in self.cors_allowed_origins.split(",")
                if origin.strip()
            ]
        if self.is_production:
            raise ConfigurationError(
                "CORS_ALLOWED_ORIGINS must be set explicitly when "
                "APP_ENV=production"
            )
        return list(DEVELOPMENT_CORS_ORIGINS)

    @property
    def cors_allow_credentials(self) -> bool:
        # A wildcard origin cannot be combined with credentials.
        return "*" not in self.cors_origins

    @property
    def ip_management_api_token_list(self) -> list[str]:
        return [
            token.strip()
            for token in self.ip_management_api_tokens.split(",")
            if token.strip()
        ]

    @property
    def alert_triage_token_roles(self) -> dict[str, str]:
        """Map of API token -> triage role (``analyst`` or ``admin``).

        Entries are comma-separated ``token=role`` pairs.  A token without a
        role, or with an unrecognized role, is treated as the least-
        privileged ``analyst`` role so a misconfiguration can never silently
        grant admin rights.
        """

        roles: dict[str, str] = {}
        for entry in self.alert_triage_api_tokens.split(","):
            entry = entry.strip()
            if not entry:
                continue
            token, separator, role = entry.partition("=")
            token = token.strip()
            role = role.strip().lower() if separator else ""
            if not token:
                continue
            roles[token] = role if role in ("analyst", "admin") else "analyst"
        return roles

    @property
    def docs_enabled(self) -> bool:
        """Interactive API docs are development-only."""
        return not self.is_production

    @property
    def database_backend(self) -> str:
        """Driver family of ``DATABASE_URL`` (e.g. ``postgresql``)."""
        return (
            self.database_url.split(":", 1)[0].split("+", 1)[0].strip()
        )

    @property
    def log_level_value(self) -> int:
        """``LOG_LEVEL`` resolved to a :mod:`logging` level constant."""
        return getattr(logging, self.log_level, logging.INFO)


settings = Settings()