"""Phase 9.2 / 9.4 — production deployment invariants.

Static checks over the deployment artefacts (production compose file, Nginx
configuration, backend image, dockerignore files) so the productionisation
guarantees cannot regress silently.  These are configuration assertions, not
runtime tests; the live deployment validation is documented in
``docs/phase-9-deployment-productionization.md``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def prod_compose() -> dict:
    return yaml.safe_load(_read(REPO_ROOT / "docker-compose.prod.yml"))


@pytest.fixture(scope="module")
def nginx_conf() -> str:
    return _read(REPO_ROOT / "nginx" / "nginx.conf")


# ---------------------------------------------------------------------------
# 9.4 — only the reverse proxy is published
# ---------------------------------------------------------------------------


def test_database_is_not_published_in_production(prod_compose):
    postgres = prod_compose["services"]["postgres"]

    assert postgres.get("ports") is None
    assert postgres["volumes"] == [
        "postgres_data:/var/lib/postgresql/data"
    ]


def test_backend_is_not_published_in_production(prod_compose):
    backend = prod_compose["services"]["backend"]

    assert backend.get("ports") is None
    assert backend["expose"] == ["8000"]


def test_only_the_proxy_publishes_a_port(prod_compose):
    published = [
        name
        for name, service in prod_compose["services"].items()
        if service.get("ports")
    ]

    assert published == ["proxy"]
    assert prod_compose["services"]["proxy"]["ports"] == [
        "${HTTP_PORT:-8080}:80"
    ]


def test_postgres_stays_persistent_and_healthy(prod_compose):
    assert "postgres_data" in prod_compose["volumes"]
    assert "healthcheck" in prod_compose["services"]["postgres"]
    assert prod_compose["services"]["backend"]["depends_on"]["postgres"] == {
        "condition": "service_healthy"
    }


def test_production_compose_requires_the_database_password(prod_compose):
    password = prod_compose["services"]["postgres"]["environment"][
        "POSTGRES_PASSWORD"
    ]

    assert ":?" in password, "POSTGRES_PASSWORD must be mandatory"


def test_proxy_waits_for_a_healthy_backend(prod_compose):
    assert prod_compose["services"]["proxy"]["depends_on"]["backend"] == {
        "condition": "service_healthy"
    }


# ---------------------------------------------------------------------------
# 9.4 — Nginx serves the dashboard and proxies the API
# ---------------------------------------------------------------------------


def test_nginx_serves_the_spa(nginx_conf):
    assert "root /usr/share/nginx/html" in nginx_conf
    assert "try_files $uri $uri/ /index.html" in nginx_conf


def test_nginx_proxies_the_api(nginx_conf):
    assert "location /api/" in nginx_conf
    assert "proxy_pass http://bfg_api" in nginx_conf
    assert "upstream bfg_api" in nginx_conf


def test_nginx_passes_health_and_readiness_through(nginx_conf):
    assert "location = /health {" in nginx_conf
    assert "proxy_pass http://bfg_api/health;" in nginx_conf
    assert "location = /health/ready {" in nginx_conf
    assert "proxy_pass http://bfg_api/health/ready;" in nginx_conf


def test_nginx_sets_safe_baseline_security_headers(nginx_conf):
    for header in (
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Content-Security-Policy",
    ):
        assert header in nginx_conf

    # The dashboard uses inline styles and Google Fonts: the CSP must allow
    # them, otherwise the production UI would break.
    assert "'unsafe-inline'" in nginx_conf
    assert "fonts.googleapis.com" in nginx_conf
    assert "fonts.gstatic.com" in nginx_conf


def test_nginx_hides_server_tokens(nginx_conf):
    assert "server_tokens off;" in nginx_conf


def test_nginx_has_a_self_contained_health_endpoint(nginx_conf):
    assert "location = /healthz" in nginx_conf


# ---------------------------------------------------------------------------
# 9.2 — backend image hardening
# ---------------------------------------------------------------------------


def test_backend_image_runs_as_non_root():
    dockerfile = _read(BACKEND_DIR / "Dockerfile")

    assert "USER 10001:10001" in dockerfile


def test_backend_image_applies_migrations_with_alembic():
    dockerfile = _read(BACKEND_DIR / "Dockerfile")

    assert "alembic upgrade head" in dockerfile
    assert "alembic stamp" in dockerfile


def test_backend_image_declares_a_liveness_healthcheck():
    dockerfile = _read(BACKEND_DIR / "Dockerfile")

    assert "HEALTHCHECK" in dockerfile
    assert "/health" in dockerfile


def test_application_startup_does_not_create_tables_by_default():
    main_py = _read(BACKEND_DIR / "app" / "main.py")
    config_py = _read(BACKEND_DIR / "app" / "core" / "config.py")

    # create_all is strictly opt-in (legacy bootstrap only) ...
    assert "create_all_on_startup: bool = False" in config_py
    assert "if settings.create_all_on_startup:" in main_py
    # ... and it is rejected outright in production.
    assert "CREATE_ALL_ON_STARTUP must be disabled when" in config_py


def test_dockerignore_files_exclude_secrets_and_dev_artifacts():
    for path in (REPO_ROOT / ".dockerignore", BACKEND_DIR / ".dockerignore"):
        content = _read(path)

        assert ".env" in content, f"{path} must exclude .env"
        assert ".git/" in content, f"{path} must exclude .git"


def test_proxy_image_builds_the_frontend_and_configures_nginx():
    dockerfile = _read(REPO_ROOT / "nginx" / "Dockerfile")

    assert "npm ci" in dockerfile
    assert "npm run build" in dockerfile
    assert "nginx/nginx.conf" in dockerfile
    assert "VITE_API_BASE_URL" in dockerfile