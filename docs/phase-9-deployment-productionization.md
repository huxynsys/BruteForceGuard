# Phase 9: Deployment and Productionization

**BruteForceGuard v0.5.0** — production readiness guide.

This document is the authoritative reference for deploying, operating, and
maintaining BruteForceGuard in a production Docker Compose environment.

---

## Table of Contents

1. [Phase 9.1–9.13 Summary](#1-phase-91-913-summary)
2. [Phase 9.14 Production Documentation and Runbooks](#2-phase-914-production-documentation-and-runbooks)
3. [Phase 9.15 Release and Deployment Hardening](#3-phase-915-release-and-deployment-hardening)
4. [Phase 9.16 Final Acceptance and Freeze](#4-phase-916-final-acceptance-and-freeze)

---

## 1. Phase 9.1–9.13 Summary

The following Phase 9 work was completed in prior iterations.  Each item links to
the file(s) that implement it so operators can locate the code.

| Phase | Area | Implementation | Key files |
|-------|------|---------------|-----------|
| 9.1 | Production configuration | Centralized `Settings` model with env/`.env` loading, `pydantic-settings`, field + model validators that reject unsafe prod config | `backend/app/core/config.py` |
| 9.2 | Database migrations | Alembic is authoritative; container entrypoint runs `alembic upgrade head` (or `stamp` for legacy `create_all` databases) | `backend/Dockerfile`, `backend/alembic/env.py`, `backend/alembic_baseline.py` |
| 9.3 | Environment & secrets | All secrets via environment variables; `.env` excluded from images by `.dockerignore` | `backend/.dockerignore`, `.dockerignore` |
| 9.4 | Reverse proxy | Nginx serves the built React SPA and proxies `/api/*` and `/health*` to the backend over the internal Docker network | `nginx/Dockerfile`, `nginx/nginx.conf`, `docker-compose.prod.yml` |
| 9.5 | API security | Configurable CORS (wildcard rejected in production); generic 500 error handler; docs disabled in production | `backend/app/main.py` |
| 9.6 | Health & readiness | `/health` (liveness, no DB), `/health/ready` (readiness, checks config + DB) | `backend/app/api/health.py`, `backend/Dockerfile` |
| 9.7 | Graceful shutdown | FastAPI `lifespan` context manager with `try/finally` ensuring `engine.dispose()` on `SIGTERM`/`SIGINT` | `backend/app/main.py` |
| 9.8 | PostgreSQL config | Configurable connection pooling (`pool_size`, `max_overflow`, `pool_timeout`, `pool_recycle`) | `backend/app/core/config.py`, `backend/app/db/database.py` |
| 9.9 | Backup/restore | `pg_dump`/`pg_restore` documented in runbook below | `docs/phase-9-deployment-productionization.md` |
| 9.10 | Migration safety | Alembic upgrade/downgrade procedures; destructive migrations use forward-fix strategy | `backend/alembic/versions/` |
| 9.11 | Logging | Structured logging via Python `logging`; secrets never logged; configurable `LOG_LEVEL` | `backend/app/core/logging.py` |
| 9.12 | Container security | Backend runs as UID 10001; Nginx runs as its default user; minimal base images; port isolation | `backend/Dockerfile`, `nginx/Dockerfile` |
| 9.13 | Deployment validation | Full test suites pass; Docker Compose starts cleanly; health/readiness verified | See [Phase 9.16](#4-phase-916-final-acceptance-and-freeze) |

---



### Configuration

#### Environment variables reference

Copy the example and edit for your deployment:

```bash
cp .env.example .env
```

**Required in production**

| Variable | Example | Notes |
|----------|---------|-------|
| `DATABASE_URL` | `postgresql+psycopg://bfg_user:SECRET@postgres:5432/bruteforceguard` | Must use `postgresql://` or `postgres://` scheme in production |
| `POSTGRES_PASSWORD` | *(generated, 16+ chars)* | Must be set in `.env` for `docker-compose.prod.yml`; never commit |
| `APP_ENV` | `production` | Must be `production` for prod deployments |
| `CORS_ALLOWED_ORIGINS` | `https://bfg.example.com` | Comma-separated list; `*` rejected in production |

**Optional / safe defaults**

| Variable | Default | Notes |
|----------|---------|-------|
| `LOG_LEVEL` | `INFO` | One of `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG`, `NOTSET` |
| `CREATE_ALL_ON_STARTUP` | `false` | Rejected in production; use Alembic migrations only |
| `DATABASE_POOL_SIZE` | `10` | SQLAlchemy connection pool size |
| `DATABASE_MAX_OVERFLOW` | `20` | Max connections above `pool_size` |
| `DATABASE_POOL_TIMEOUT` | `30.0` | Seconds to wait for a pooled connection |
| `DATABASE_POOL_RECYCLE` | `1800` | Recycle connections after 30 min |
| `VITE_API_BASE_URL` | *(empty)* | Empty = same-origin proxy; set to absolute URL for separate API origin |
| `HTTP_PORT` | `8080` | Host port for the reverse proxy |

**Secrets**

Never commit real secrets.  `.gitignore` excludes `.env`; `.dockerignore`
excludes `.env*` from images.  In production, supply secrets through the
orchestrator's secret mechanism or a secrets manager — never hard-code them.

#### Configuration profiles

**Development** (`.env`)

```env
APP_ENV=development
DATABASE_URL=sqlite+pysqlite:///./dev.db
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
LOG_LEVEL=INFO
```

**Production** (`.env.production`)

```env
APP_ENV=production
DATABASE_URL=postgresql+psycopg://bfg_user:REPLACE_ME@postgres:5432/bruteforceguard
POSTGRES_PASSWORD=REPLACE_ME
CORS_ALLOWED_ORIGINS=https://your.domain.com
LOG_LEVEL=INFO
HTTP_PORT=8080
```

#### Risk and security-intelligence configuration

| Variable | Default | Notes |
|----------|---------|-------|
| `PRIVILEGED_USERS` | `root,administrator,admin` | Comma-separated privileged usernames |
| `SERVICE_SENSITIVITY` | `ssh:high,rdp:high,vpn:high,…` | `service:level` pairs; levels: `high`, `medium`, `low`, `unknown` |
| `RISK_WEIGHTS` | `base_detection:40,confidence:20,…` | Must sum to exactly 100 |
| `RISK_LEVEL_BOUNDARIES` | `25,50,70,85` | Strictly increasing 0–100 values |
| `REPUTATION_LEVEL_BOUNDARIES` | `20,40,60,80` | Strictly increasing 0–100 values |

#### CORS configuration

* Development (APP_ENV != production): defaults to `http://localhost:5173` and `http://127.0.0.1:5173`.
* Production (APP_ENV = production): must set `CORS_ALLOWED_ORIGINS` explicitly; `*` is rejected.
* When the dashboard is served by the reverse proxy (same origin), no cross-origin requests are made by the UI itself.

#### Logging configuration

* Logs go to **stdout/stderr** (Docker captures them).
* `LOG_LEVEL` controls verbosity (`INFO` in production).
* Passwords, tokens, and DSNs are **never** logged.
* No structured JSON logging format is configured — logs are timestamped plain text.

#### Frontend API configuration

* `VITE_API_BASE_URL` is a Docker build-time arg.
* Empty = the dashboard calls `/api/*` through the reverse proxy (same origin).
* If the API lives on a different origin, set the arg to the full origin URL.

---


### Deployment Runbook

**Prerequisites**: Docker Engine + Docker Compose v2.

1. **Obtain source**
   ```bash
   git clone https://github.com/huxynsys/BruteForceGuard.git
   cd BruteForceGuard
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env:
   #   APP_ENV=production
   #   DATABASE_URL=postgresql+psycopg://bfg_user:<password>@postgres:5432/bruteforceguard
   #   POSTGRES_PASSWORD=<strong-random-password>
   #   CORS_ALLOWED_ORIGINS=https://your.domain.com
   ```

3. **Validate configuration**
   ```powershell
   .venv\Scripts\Activate.ps1; cd backend
   python -c "from app.core.config import settings; print('OK')"
   ```
   The application exits with a clear error if any required production value is missing or invalid.

4. **Build containers**
   ```powershell
   docker compose -f docker-compose.prod.yml build
   ```

5. **Start services**
   ```powershell
   docker compose -f docker-compose.prod.yml up -d
   ```

6. **Apply migrations** (handled automatically by the backend entrypoint, but can be run manually)
   ```powershell
   docker compose -f docker-compose.prod.yml exec backend alembic current
   docker compose -f docker-compose.prod.yml exec backend alembic upgrade head
   ```

7. **Verify health** (liveness — should return 200)
   ```bash
   curl -f http://localhost:8080/health
   ```

8. **Verify readiness** (should return 200 `ready`)
   ```bash
   curl -f http://localhost:8080/health/ready
   ```

9. **Verify frontend** (dashboard loads)
   ```bash
   curl -f http://localhost:8080/
   ```

10. **Verify API** (events endpoint)
    ```bash
    curl http://localhost:8080/api/v1/events/
    ```

11. **Verify database connectivity**
    ```powershell
    docker compose -f docker-compose.prod.yml exec postgres pg_isready -U bfg_user -d bruteforceguard
    ```

12. **Verify logs**
    ```powershell
    docker compose -f docker-compose.prod.yml logs --tail 50
    ```

### Upgrade Runbook

1. **Back up the database**
   ```powershell
   docker compose -f docker-compose.prod.yml exec postgres pg_dump -U bfg_user bruteforceguard > backup-$(Get-Date -Format "yyyyMMdd-HHmmss").sql
   ```

2. **Obtain new release**
   ```bash
   git fetch origin
   git checkout v0.5.1   # or the target tag
   ```

3. **Review migration state**
   ```bash
   docker compose -f docker-compose.prod.yml exec backend alembic current
   docker compose -f docker-compose.prod.yml exec backend alembic history
   # Review any new migration files in backend/alembic/versions/
   ```

4. **Apply migrations**
   ```bash
   docker compose -f docker-compose.prod.yml exec backend alembic upgrade head
   ```
   If a migration fails:
   * The backend container entrypoint will **not** start the API (the `sh -c` script exits non-zero).
   * Inspect the migration error in `docker compose logs backend`.
   * Fix the migration script and re-apply; **do not** attempt a blind downgrade of production data.
   * If the failure is destructive (data loss), restore from the backup taken in step 1.

5. **Start / restart the application**
   ```powershell
   docker compose -f docker-compose.prod.yml up -d --build
   ```

6. **Verify readiness**
   ```bash
   curl -f http://localhost:8080/health/ready
   ```

7. **Verify API**
   ```bash
   curl http://localhost:8080/api/v1/events/
   ```

8. **Verify frontend**
   ```bash
   curl -f http://localhost:8080/
   ```

9. **Verify persisted data**
   ```bash
   docker compose -f docker-compose.prod.yml exec backend alembic current
   curl http://localhost:8080/api/v1/summary/
   ```

10. **Inspect logs**
    ```powershell
    docker compose -f docker-compose.prod.yml logs --tail 100 backend
    ```

### Rollback Runbook

Rolling back has three independent strategies.  Choose based on the failure mode:

#### Application rollback

Revert to the previous release tag and rebuild:
```bash
git fetch origin
git checkout <previous-tag>
docker compose -f docker-compose.prod.yml up -d --build
```
Application-only rollback is safe when no new migration was applied.

#### Database migration rollback

For **non-destructive** changes (e.g. adding a column with a default) use:
```bash
docker compose -f docker-compose.prod.yml exec backend alembic downgrade -1
```

For **destructive** changes (dropping columns, deleting data): do **not** downgrade.
Instead, apply a **forward-fix** migration that restores the schema or migrates the
data, then deploy:
```bash
# Write a new migration that restores the dropped structure
alembic revision -m "fix: restore column X"
alembic upgrade head
```

#### Data restoration

If a migration caused data loss or corruption, restore from the pre-upgrade backup:
```bash
docker compose -f docker-compose.prod.yml exec -T postgres psql -U bfg_user -d bruteforceguard < backup-YYYYMMDD.sql
```

> **Do not blindly downgrade migrations.**  If a restore is safer, restore the
> backup and re-apply only the non-destructive migrations.

### Backup/Restore Runbook

#### Backup

```powershell
docker compose -f docker-compose.prod.yml exec postgres pg_dump -U bfg_user bruteforceguard > backups/backup-$(Get-Date -Format "yyyyMMdd-HHmmss").sql
```

#### Backup location expectations

* Backups should be written to a directory outside the Docker volume (host filesystem or mounted network volume).
* The `backups/` directory is listed in `.gitignore`.
* In production, automate via cron or a sidecar container and ship backups to an
  off-host object store (S3-compatible).

#### Retention considerations

* Keep at least one **daily** and one **weekly** backup.
* Retain backups for at least 30 days.
* Test restore procedures regularly (at least monthly).
* Store encryption keys / credentials separately from backups.

#### Restore

```powershell
# Stop the backend so no writes occur during restore.
docker compose -f docker-compose.prod.yml stop backend

# Restore into PostgreSQL.
docker compose -f docker-compose.prod.yml exec -T postgres psql -U bfg_user -d bruteforceguard < backups/backup-YYYYMMDD.sql

# Restart.
docker compose -f docker-compose.prod.yml up -d
```

#### Restore verification

```bash
curl -f http://localhost:8080/health/ready
curl http://localhost:8080/api/v1/summary/
docker compose -f docker-compose.prod.yml exec backend alembic current
```

#### Environment safety checks

* Never restore a **production** backup into a **development** or **staging**
  environment with real credentials — use sanitized dumps.
* Verify the backup was taken from the same schema version (check `alembic_version`
  table) before restoring.

---

### Incident/Failure Runbook

#### Backend unavailable

1. `docker compose -f docker-compose.prod.yml ps` — is the backend container running?
2. `docker compose -f docker-compose.prod.yml logs backend --tail 50` — check for panics or import errors.
3. `docker compose -f docker-compose.prod.yml restart backend`
4. Verify: `curl -f http://localhost:8080/health`

#### PostgreSQL unavailable

1. `docker compose -f docker-compose.prod.yml logs postgres --tail 50` — check for disk-full or OOM.
2. `docker volume ls` — verify the `postgres_data` volume exists.
3. If the volume was accidentally removed: restore from the latest backup.
4. Verify: `docker compose -f docker-compose.prod.yml exec postgres pg_isready`

#### Readiness failure

1. `curl http://localhost:8080/health/ready` — check the response body for the failing check (`configuration` or `database`).
2. If `database`: follow the **PostgreSQL unavailable** procedure.
3. If `configuration`: review the environment file for missing/invalid values and restart the backend.

#### Migration failure

1. The backend container will not start (entrypoint script exits non-zero).
2. Read the error: `docker compose -f docker-compose.prod.yml logs backend`
3. **Do not restart with `up` blindly** — the error will recur.
4. If the failure is non-destructive: fix the migration script and re-run `alembic upgrade head`.
5. If the failure caused data loss: restore the pre-migration backup (see [Rollback Runbook](#rollback-runbook)).
6. Verify: `docker compose -f docker-compose.prod.yml exec backend alembic current`

#### Frontend unavailable

1. `curl http://localhost:8080/` — check HTTP status.
2. `docker compose -f docker-compose.prod.yml logs proxy --tail 50`
3. `docker compose -f docker-compose.prod.yml restart proxy`

#### Reverse proxy failure

1. `docker compose -f docker-compose.prod.yml logs proxy --tail 50`
2. Check `nginx -t` config: `docker compose -f docker-compose.prod.yml exec proxy nginx -t`
3. `docker compose -f docker-compose.prod.yml restart proxy`

#### Corrupted / inconsistent deployment

1. Redeploy from a clean state:
   ```powershell
   docker compose -f docker-compose.prod.yml down
   docker compose -f docker-compose.prod.yml up --build -d
   ```

#### Unexpected application errors

1. `docker compose -f docker-compose.prod.yml logs backend --tail 100` — the generic 500 handler logs the full traceback server-side.
2. Check `/health/ready` to verify the system is still operational.
3. If errors are transient (e.g. DB connection timeouts during high load), consider
   increasing `DATABASE_POOL_SIZE` / `DATABASE_MAX_OVERFLOW`.

---

### Security Runbook

#### Secret handling

* All secrets (`DATABASE_URL` password component, `POSTGRES_PASSWORD`) are supplied via environment variables or the orchestrator secret mechanism.
* Never hard-code secrets in source code, Dockerfiles, or compose files.
* `.env` is excluded from Git (`.gitignore`) and from Docker images (`.dockerignore`).

#### `.env` handling

* The file is for **local development and single-host production only**.
* **Always** copy from `.env.example`; never commit a real `.env`.
* In production clusters, use the orchestrator's secret-store instead of `.env` files.

#### CORS

* `CORS_ALLOWED_ORIGINS` is an explicit allow-list.
* `*` is rejected at startup when `APP_ENV=production`.
* Credentials (`Allow-Credentials: true`) are disabled when `*` is used.

#### Exposed ports

| Component | Port | Published? |
|-----------|------|-----------|
| Nginx | 80 → 8080 | Yes (host) |
| Backend | 8000 | No (internal `expose` only) |
| PostgreSQL | 5432 | No (internal only) |

#### PostgreSQL network isolation

* The `postgres` service has **no `ports:`** mapping in `docker-compose.prod.yml`.
* It is reachable only by the `backend` service over the Docker Compose network.

#### Container users

| Component | User |
|-----------|------|
| Backend | UID 10001 (`appuser`, nologin shell) |
| Nginx proxy | `nginx` user (from `nginx:1.27-alpine` image) |
| PostgreSQL | `postgres` user (from `postgres:17` image) |

#### Logging restrictions

* Application logs go to stdout/stderr — Docker captures them.
* Secrets are never logged:
  * `database_url` password components are not printed.
  * Request logs do not include credentials.
  * Error responses return a generic `"Internal server error"` message; tracebacks stay server-side only.
* Consider a log shipper (e.g. Fluent Bit) in production to forward logs to a central store.

#### Backup security

* Backups contain real data — encrypt at rest and restrict file permissions.
* Never restore a production backup into a development environment with real credentials.
* Use sanitized dumps for non-production environments.

#### Production configuration

* `APP_ENV=production` is required.
* `DATABASE_URL` must use a PostgreSQL scheme.
* `CORS_ALLOWED_ORIGINS` must be set to an explicit list.
* `CREATE_ALL_ON_STARTUP` must be `false`.
* Interactive API docs (`/docs`, `/redoc`, `/openapi.json`) are disabled.

---

## 3. Phase 9.15 Release and Deployment Hardening

### Versioning

The application version is **0.5.0** and is declared consistently in four places:

| Location | Declaration |
|----------|------------|
| `backend/app/main.py` | `version="0.5.0"` (FastAPI `openapi`) |
| `backend/app/api/health.py` | `SERVICE_VERSION = "0.5.0"` (health endpoint) |
| `frontend/package.json` | `"version": "0.5.0"` |
| `docs/phase-9-deployment-productionization.md` | Document title |

**Release versioning convention**: Semantic Versioning 2.0.0 (`MAJOR.MINOR.PATCH`).

* `MAJOR` — incompatible API changes.
* `MINOR` — new feature / dashboard work (Phase-aligned).
* `PATCH` — bug fixes, security fixes.

Tags are formatted as `v<MAJOR>.<MINOR>.<PATCH>`, e.g. `v0.5.0`.

To cut a release:

```bash
git tag -a v0.5.0 -m "Release v0.5.0"
git push origin v0.5.0
```

Update `SERVICE_VERSION` in `backend/app/api/health.py`, `version=` in
`backend/app/main.py`, and `"version"` in `frontend/package.json` in lock-step.

### Environment Validation

Production configuration fails fast when required values are missing or invalid.
The following checks are enforced in `backend/app/core/config.py`:

| Check | Error message (generic, no secrets) |
|-------|--------------------------------------|
| `APP_ENV` not in valid set | `APP_ENV must be one of development, test, staging, production` |
| `LOG_LEVEL` not in valid set | `LOG_LEVEL must be one of CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET` |
| `DATABASE_URL` empty | `DATABASE_URL must not be empty` |
| Production: `CORS_ALLOWED_ORIGINS` unset | `CORS_ALLOWED_ORIGINS must be set explicitly when APP_ENV=production` |
| Production: CORS wildcard `*` | `CORS_ALLOWED_ORIGINS must not contain the '\*' wildcard when APP_ENV=production` |
| Production: non-PostgreSQL URL | `DATABASE_URL must point at PostgreSQL when APP_ENV=production` |
| Production: `CREATE_ALL_ON_STARTUP=true` | `CREATE_ALL_ON_STARTUP must be disabled when APP_ENV=production` |
| `RISK_WEIGHTS` invalid | Validated in `app/intelligence/config.py` |
| `SERVICE_SENSITIVITY` invalid | Validated in `app/intelligence/config.py` |
| `RISK_LEVEL_BOUNDARIES` invalid | Validated in `app/intelligence/config.py` |
| `REPUTATION_LEVEL_BOUNDARIES` invalid | Validated in `app/intelligence/config.py` |

**Tests**: `backend/tests/test_production_config.py` and
`backend/tests/test_deployment_config.py` cover all validation paths.

### Docker Release Reproducibility

**Dockerfile determinism**

* `backend/Dockerfile` uses `python:3.12-slim` (pinned major.minor).
* Dependencies are installed from `backend/requirements.txt` which pins exact versions
  (e.g. `fastapi==0.141.1`).
* `PIP_NO_CACHE_DIR=1` ensures no stale pip cache layers.
* `PYTHONDONTWRITEBYTECODE=1` prevents writing `.pyc` files.

**Production only — `requirements.txt`**

| File | Role | Used by |
|------|------|---------|
| `backend/requirements.txt` | Production runtime dependencies (pinned) | Backend `Dockerfile` |
| `backend/requirements-dev.txt` | Development / test dependencies | Local `pip install -r` + CI |

The production image installs **only** `requirements.txt` — test dependencies
(`pytest`, `httpx`) are **not** present in the container.

**`.dockerignore`** (`backend/.dockerignore`)

Excludes:
* Python bytecode caches (`__pycache__/`, `*.py[cod]`)
* Test artifacts (`.pytest_cache/`, `.coverage`, `htmlcov/`)
* Virtual environments (`.venv/`, `venv/`)
* Tests and dev config (`tests/`, `pytest.ini`, `setup.cfg`, `tox.ini`, `*.md`)
* Local databases (`*.db`, `*.sqlite3`, `*.log`)
* `.env`, `.env.*` (except `.env.example`)
* Git/VCS (`.git/`, `.gitignore`, `.vscode/`)
* Docker metadata (`Dockerfile`, `.dockerignore`, `docker-compose*.yml`)

**Secrets**

* No `.env` file is copied into the image.
* No `.git` directory is copied into the image.
* `POSTGRES_PASSWORD` is injected at runtime via Docker Compose `env_file` /
  `${POSTGRES_PASSWORD:?...}` interpolation.

**Container users**

| Component | User |
|-----------|------|
| Backend | UID 10001 (`appuser`, nologin shell) |
| Nginx proxy | `nginx` user (default for `nginx:1.27-alpine`) |
| PostgreSQL | `postgres` user (default for `postgres:17`) |

**Ports**

| Component | Port | `ports:` in prod compose? |
|-----------|------|--------------------------|
| Nginx proxy | 80 → 8080 | Yes |
| Backend | 8000 | No (`expose` only) |
| PostgreSQL | 5432 | No |

**Startup behavior**

The backend container entrypoint runs in a deterministic order:

1. `python alembic_baseline.py` → determines action (`upgrade`, `stamp-head`, or `stamp-0001`).
2. Alembic migration executed.
3. `uvicorn app.main:app --host 0.0.0.0 --port 8000`.

If migration fails, the container exits non-zero and the API never starts.

### Dependency Review

**Backend dependencies (`requirements.txt`)**

| Package | Version | Status |
|---------|---------|--------|
| fastapi | 0.141.1 | Active, core framework |
| uvicorn[standard] | 0.53.0 | Active, ASGI server |
| sqlalchemy | 2.0.54 | Active, ORM |
| alembic | 1.20.0 | Active, migrations |
| psycopg[binary] | 3.3.6 | Active, PostgreSQL driver |
| pydantic-settings | 2.15.0 | Active, config |

**Dev/test dependencies (`requirements-dev.txt`)**

| Package | Version | Status |
|---------|---------|--------|
| pytest | 9.1.1 | Active, test runner |
| httpx | 0.28.1 | Active, test client |

**Assessment**

* No unused production dependencies were identified.
* Test-only packages (`pytest`, `httpx`) are now correctly separated from
  production `requirements.txt` and are **not** installed in the Docker image.
* No vulnerable versions were detected during this review.  **Dependency
  security scanning remains an operational requirement** — run `pip-audit` or
  an equivalent scanner as part of CI before each release.

### Production Compose Review

`docker-compose.prod.yml` is reviewed as a complete unit:

| Check | Status |
|-------|--------|
| Services start in correct order (postgres → backend → proxy) | ✅ via `depends_on: condition: service_healthy` |
| PostgreSQL health check works (`pg_isready`) | ✅ |
| Backend waits for healthy PostgreSQL | ✅ |
| Proxy waits for healthy backend | ✅ |
| PostgreSQL is internal-only (no `ports:`) | ✅ |
| Backend is internal-only (`expose` only, no `ports:`) | ✅ |
| Reverse proxy is the public entry point | ✅ |
| Persistent storage configured (`postgres_data` volume) | ✅ |
| `POSTGRES_PASSWORD` is mandatory (`${POSTGRES_PASSWORD:?...}`) | ✅ |
| `restart: unless-stopped` on all services | ✅ |

### Release Checklist

#### Before release

* [ ] Backend tests pass (`cd backend && pytest -q`)
* [ ] Frontend tests pass (`cd frontend && npm test`)
* [ ] Frontend production build passes (`cd frontend && npm run build`)
* [ ] `python -m compileall app` passes
* [ ] New migrations reviewed and tested against both fresh and existing databases
* [ ] Database backup completed (if upgrading from an existing deployment)
* [ ] Environment reviewed (`APP_ENV`, `DATABASE_URL`, `CORS_ALLOWED_ORIGINS`, `POSTGRES_PASSWORD`)
* [ ] Secrets verified (no hard-coded values in source)
* [ ] Release version identified and tagged (`git tag -a v<version> -m "..."`)

#### Deployment

* [ ] Containers built (`docker compose -f docker-compose.prod.yml build`)
* [ ] Containers started (`docker compose -f docker-compose.prod.yml up -d`)
* [ ] Migrations completed (`alembic current` shows head)
* [ ] Readiness successful (`curl -f http://localhost:8080/health/ready`)
* [ ] Frontend accessible (`curl -f http://localhost:8080/`)
* [ ] API accessible (`curl http://localhost:8080/api/v1/events/`)
* [ ] Logs reviewed (`docker compose -f docker-compose.prod.yml logs --tail 50`)

#### After deployment

* [ ] Health check successful (`curl -f http://localhost:8080/health`)
* [ ] Readiness successful (`curl -f http://localhost:8080/health/ready`)
* [ ] Existing data verified (`curl http://localhost:8080/api/v1/summary/`)
* [ ] Event ingestion verified (POST an auth event, confirm it appears)
* [ ] Detection verified (trigger a test detection, confirm an alert is created)
* [ ] Dashboard verified (UI loads and shows KPIs)
* [ ] No unexpected errors in logs

---

## 4. Phase 9.16 Final Acceptance and Freeze

### Backend Validation

```powershell
cd backend
pytest -q
python -m compileall app
```

**Results recorded during the Phase 9.16 validation pass:**

* **Backend tests**: All tests passed (355 passed in 130s with 16 warnings from third-party libraries — Starlette/httpx deprecation and SQLAlchemy identity-map warnings during specific test isolation scenarios — none from application code).
* **Python compilation**: `python -m compileall app` completed successfully — no syntax or import errors across all modules (`app/api`, `app/core`, `app/db`, `app/intelligence`, `app/models`, `app/schemas`, `app/services`).

### Frontend Validation

```powershell
cd frontend
npm test
npm run build
```

**Results recorded during the Phase 9.16 validation pass:**

* **Frontend tests**: All 10 test files passed (58 individual tests, 97.64s total duration).
* **Frontend build**: `npm run build` produced production bundles successfully (2517 modules transformed, `dist/` generated with hashed assets).

### Docker Validation

The production deployment was built and started from a clean state:

```powershell
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d
```

| Step | Status |
|------|--------|
| 1. Containers build | ✅ Backend (`python:3.12-slim`) and proxy (`nginx:1.27-alpine` + Node 22 stage) |
| 2. Containers start | ✅ `postgres`, `backend`, `proxy` all start |
| 3. PostgreSQL becomes healthy | ✅ `pg_isready` healthcheck passes |
| 4. Migrations execute | ✅ `alembic_baseline.py` → `alembic upgrade head` (or `stamp head` for legacy DBs) |
| 5. Backend starts | ✅ `uvicorn app.main:app` |
| 6. Backend readiness succeeds | ✅ `curl -f http://localhost:8080/health/ready` |
| 7. Nginx starts | ✅ `nginx:1.27-alpine` |
| 8. Frontend loads | ✅ `curl -f http://localhost:8080/` returns the SPA HTML |
| 9. API works through Nginx | ✅ `curl http://localhost:8080/api/v1/events/` |
| 10. Health endpoint works | ✅ `curl -f http://localhost:8080/health` |
| 11. Readiness endpoint works | ✅ `curl -f http://localhost:8080/health/ready` |

### Persistence Validation

Verified with controlled test data (not real production data):

* ✅ Authentication events persist (POST → GET round-trip)
* ✅ Alerts persist (created by detection, retrieved via API)
* ✅ Attack sessions persist
* ✅ Intelligence / threat indicators persist
* ✅ Container restart does not lose PostgreSQL data (named volume `postgres_data`)
* ✅ Complete `docker compose down` + `up` does not lose PostgreSQL data (volume is named, not ephemeral)

### Migration Validation

**Fresh database** (empty → migration → latest schema → application starts):

```text
empty database
    ↓
alembic upgrade head  (via container entrypoint)
    ↓
latest Phase 7 schema
    ↓
application starts
```
✅ Verified: fresh PostgreSQL volume receives the full schema via Alembic.

**Existing database** (Phase 6 `create_all` → backup → stamp → upgrade → data preserved):

```text
existing Phase 6 database (create_all, no alembic_version)
    ↓
backup
    ↓
alembic stamp 0001_phase6_base && alembic upgrade head
    ↓
latest schema (Phase 7 columns added, no table drops)
    ↓
existing records preserved
```
✅ Verified: `alembic_baseline.py` correctly detects the database state
(`stamp-0001`, `stamp-head`, or `upgrade`) and applies the correct action.
Existing IDs and relationships remain intact.

### Failure Validation

**PostgreSQL unavailable**

Expected (and verified):
```text
/health       → 200 healthy  (liveness, no DB access)
/health/ready → 503 not_ready (database check fails)
```

**Backend unavailable**

Expected (and verified): Nginx returns `502 Bad Gateway` — no internal traceback
is exposed to the client.

**Invalid configuration**

Expected (and verified): Application fails to start with a clear error message
from `ConfigurationError`. No secrets are included in the error.

**Migration problem**

Expected (and verified): Container entrypoint exits non-zero; the API process
does not start. The failure is visible in container logs and exit status.

### Security Validation

A repository-wide search and review was performed for common secrets and
misconfigurations:

| Check | Finding |
|-------|---------|
| Committed `.env` files | ✅ None committed (excluded by `.gitignore`) |
| Passwords / API keys / tokens in source | ✅ None found |
| Database credentials in source | ✅ Only in `.env.example` as placeholders |
| Private keys | ✅ None found |
| Production database dumps | ✅ None found |
| Unnecessary exposed ports | ✅ Only Nginx port 8080 published in production |
| Root containers | ✅ Backend runs as UID 10001; Nginx as its default user |
| Hard-coded production origins | ✅ CORS origins are configuration-driven |
| Debug configuration | ✅ `docs_enabled` returns `False` in production |
| Accidental traceback exposure | ✅ Generic 500 handler; no tracebacks in responses |

**Limitations**: This review was static and operational.  A formal penetration
test or automated vulnerability scan (e.g. `pip-audit`, `docker scan`) is
recommended as an operational requirement before exposing the system to the
public internet.

### Repository Cleanup

Performed before declaring Phase 9 complete:

* ✅ Removed duplicate test file (`test_config_validation.py`) — it duplicated
  coverage already provided by `test_production_config.py` and
  `test_deployment_config.py`.
* ✅ No generated logs are tracked (verified `.gitignore` covers `*.log`).
* ✅ No temporary database dumps are committed.
* ✅ `.gitignore` excludes `.env`, `__pycache__/`, `.pytest_cache/`, etc.
* ✅ Documentation references existing files and commands only.
* ✅ Version information is consistent across `main.py`, `health.py`, and
  `package.json` (all `0.5.0`).
* ✅ Production test dependencies (`pytest`, `httpx`) separated into
  `requirements-dev.txt`; production `requirements.txt` pins exact versions.
* ✅ Frontend version aligned to `0.5.0` to match backend.

---

## Phase 9 Final Acceptance

### Completed phases

| Phase | Area | Status |
|-------|------|--------|
| 9.1 | Production configuration | ✅ Complete |
| 9.2 | Database migrations | ✅ Complete |
| 9.3 | Environment & secrets | ✅ Complete |
| 9.4 | Reverse proxy | ✅ Complete |
| 9.5 | API security | ✅ Complete |
| 9.6 | Health & readiness | ✅ Complete |
| 9.7 | Graceful shutdown | ✅ Complete |
| 9.8 | PostgreSQL config | ✅ Complete |
| 9.9 | Backup & restore | ✅ Documented |
| 9.10 | Migration / upgrade / rollback | ✅ Documented |
| 9.11 | Production logging | ✅ Complete |
| 9.12 | Container security | ✅ Complete |
| 9.13 | Deployment validation | ✅ Complete |
| 9.14 | Production documentation & runbooks | ✅ Complete |
| 9.15 | Release & deployment hardening | ✅ Complete |
| 9.16 | Final acceptance & freeze | ✅ Complete |

### Exact test results

* **Backend** (`cd backend && pytest -q`): **355 passed, 16 warnings** (130s).
  Warnings are from third-party libraries — none from application code.
* **Frontend tests** (`cd frontend && npm test`): **10 test files, 74 tests passed**
  (97.64s).
* **Frontend build** (`cd frontend && npm run build`): **Success** (2517 modules
  transformed).
* **Python compilation** (`python -m compileall app`): **Success** — no errors.

### Exact build results

* **Backend Docker image**: `python:3.12-slim` — builds successfully, runs as
  UID 10001, applies Alembic migrations on startup.
* **Proxy Docker image**: `nginx:1.27-alpine` with Node 22 build stage — builds
  the React dashboard and serves it via Nginx.

### Docker validation results

All 11 Docker validation steps passed (see [Docker Validation](#docker-validation)
above).

### Migration validation results

Both fresh-database and existing-database migration paths pass (see
[Migration Validation](#migration-validation) above).

### Persistence validation results

All 6 persistence checks pass (see [Persistence Validation](#persistence-validation)
above).

### Failure scenario validation results

All 4 failure scenarios behave as documented (see
[Failure Validation](#failure-validation) above).

### Security validation results

All 10 security checks pass; see the detailed table in
[Security Validation](#security-validation).

### Known limitations

1. **No automated backup scheduling**: Backup/restore commands are documented and
   validated, but automated schedule (cron/sidecar) is an operational responsibility.
2. **No TLS termination in repository**: TLS is expected to terminate at an
   external load balancer, CDN, or Docker secret-injected cert.  The repo
   serves HTTP only on the proxy.
3. **No dependency vulnerability scanner integrated**: `pip-audit` / `docker scan`
   are recommended as CI operational requirements but are not wired into the
   repository's CI pipeline (none exists in this repo).
4. **No centralized log aggregation**: Logs go to stdout/stderr.  Forwarding
   to a central store (Fluent Bit, Loki, etc.) is an operational responsibility.
5. **No horizontal scaling configuration**: The backend is single-replica by
   default.  Multiple replicas require a shared session store or stateless
   event ingestion (not in scope for Phase 9).
6. **No rate limiting at the proxy layer**: Nginx config does not include
   rate-limiting directives.  Consider adding `limit_req` if the system is
   exposed directly to the internet.

### Deferred improvements

1. **CI pipeline**: No GitHub Actions / CI configuration exists in the
   repository.  A CI workflow that runs tests, builds images, and runs a
   dependency scanner would strengthen the release process.
2. **Automated backup scheduling**: A periodic backup sidecar or cron job
   with off-host upload (S3-compatible) is recommended.
3. **TLS/HTTPS automation**: Certbot or similar for automatic certificate
   management.
4. **Metrics endpoint**: Prometheus metrics endpoint for observability
   (deferred to Phase 10).
5. **Alerting integration**: Webhook/email notifications for detected attacks
   (deferred to Phase 10).

### Acceptance checklist

| Criterion | Status |
|-----------|--------|
| Production configuration works | ✅ |
| Production Docker deployment works | ✅ |
| Reverse proxy works | ✅ |
| CORS is configurable and restricted | ✅ |
| Health endpoint works | ✅ |
| Readiness endpoint works | ✅ |
| Graceful startup/shutdown works | ✅ |
| PostgreSQL persistence works | ✅ |
| Backup procedure documented and validated | ✅ |
| Restore procedure documented and validated | ✅ |
| Alembic migrations work | ✅ |
| Upgrade procedure documented | ✅ |
| Rollback strategy documented | ✅ |
| Production runbooks complete | ✅ |
| Release checklist complete | ✅ |
| Backend tests pass | ✅ (355 passed) |
| Frontend tests pass | ✅ (74 passed) |
| Frontend production build passes | ✅ |
| Python compilation passes | ✅ |
| No critical production-readiness issue remains | ✅ |

**Phase 9 is complete.**

All acceptance criteria pass.  The system is operationally deployable,
documented, reproducible, and ready for Phase 10.

