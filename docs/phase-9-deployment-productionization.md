# Phase 9 — Deployment & Productionization

This document covers **Phase 9.1–9.6 only**: production configuration, Docker
hardening, the frontend production build, the reverse proxy, CORS/API
security hardening and health/readiness probes.

Phase 9 is **not** complete: sections 9.7 and later are listed at the end and
remain open. Nothing in Phase 9.1–9.6 changes the Phase 1–8 detection,
correlation, intelligence or API behaviour; no new infrastructure
(Kubernetes, Redis, Kafka, Celery, Elasticsearch, microservices) was
introduced, and no existing test was weakened or removed.

## 1. Architecture (production)

```
        Browser
           │  http(s)://host/
           ▼
   ┌──────────────────────────┐
   │  proxy (nginx:1.27-alpine)│  ← only service with a published port
   │  • serves dist/ (SPA)     │
   │  • security headers       │
   └───────────┬──────────────┘
               │ /api/*, /health, /health/ready
               ▼           (internal Docker network only)
   ┌──────────────────────────┐
   │  backend (FastAPI)        │  ← no published port, non-root UID 10001
   │  • alembic upgrade head   │     (entrypoint runs migrations first)
   │  • uvicorn :8000          │
   └───────────┬──────────────┘
               │ DATABASE_URL
               ▼           (internal Docker network only)
   ┌──────────────────────────┐
   │  postgres:17              │  ← no published port, named volume
   └──────────────────────────┘
```

Only `proxy` publishes a port (`${HTTP_PORT:-8080}:80`). PostgreSQL and the
API are unreachable from the host or the internet.

## 2. 9.1 — Production configuration

`backend/app/core/config.py` is the single source of truth. Every setting is
declared there and read from the environment / `.env`:

| Variable | Purpose | Default |
|---|---|---|
| `APP_ENV` | `development` \| `test` \| `staging` \| `production` | `development` |
| `DATABASE_URL` | SQLAlchemy URL (required) | — |
| `LOG_LEVEL` | `CRITICAL`…`DEBUG` | `INFO` |
| `CORS_ALLOWED_ORIGINS` | comma-separated browser origins | dev origins |
| `PRIVILEGED_USERS` | comma-separated privileged accounts | `root,administrator,admin` |
| `SERVICE_SENSITIVITY` | `service:level` pairs | Phase 7 defaults |
| `RISK_WEIGHTS` | risk factors, must sum to 100 | `40/20/15/15/10` |
| `RISK_LEVEL_BOUNDARIES` | 4 ascending values | `25,50,70,85` |
| `REPUTATION_LEVEL_BOUNDARIES` | 4 ascending values | `20,40,60,80` |
| `CREATE_ALL_ON_STARTUP` | legacy bootstrap escape hatch | `false` |

Behaviour:

- **Development defaults are unchanged.** With `APP_ENV` unset the CORS
  origins are the Vite dev origins (`http://localhost:5173`,
  `http://127.0.0.1:5173`), docs stay enabled, and the Phase 1–8 test suite
  runs exactly as before.
- **The Phase 7 intelligence tunables are now declared centrally.** The
  loaders in `app/intelligence/config.py` read `app.core.config.settings`
  first (with a live-environment fallback so Phase 7's environment-driven
  tests behave identically). Validation is unchanged: weights must define
  exactly the five factors and sum to 100, boundaries must be strictly
  increasing within 0–100, sensitivity levels must be known values.
- **Invalid configuration fails fast** with an explicit message. Rejected at
  startup: an unknown `APP_ENV`, an unknown `LOG_LEVEL`, an empty
  `DATABASE_URL`, and — when `APP_ENV=production` — a missing
  `CORS_ALLOWED_ORIGINS`, a `*` wildcard origin, a non-PostgreSQL
  `DATABASE_URL`, or `CREATE_ALL_ON_STARTUP=true`.
- `LOG_LEVEL` is applied by `app.core.logging.configure_logging()`, called
  when the application is imported.
- `.env.example` documents every variable with safe placeholder values;
  secrets stay in the (untracked) `.env`.

## 3. 9.2 — Docker hardening

`backend/Dockerfile`:

- runs as **UID 10001** (`USER 10001:10001`); the user is created when the
  base image provides `useradd`, and the numeric UID is used either way, so
  the build cannot fail because of user-management tooling;
- declares a `HEALTHCHECK` that probes `/health` (liveness, no database);
- keeps **Alembic as the authoritative migration mechanism**: the entrypoint
  resolves the correct baseline (`alembic_baseline.py`) and runs
  `alembic upgrade head` / `alembic stamp …` before starting uvicorn.

`backend/.dockerignore` (new) and the root `.dockerignore` (new) keep the
virtualenv, tests, caches, `.git` and — importantly — `.env` out of the
images.

**Startup no longer creates tables.** `Base.metadata.create_all()` was
removed from the application lifespan; it now runs only when
`CREATE_ALL_ON_STARTUP=true` (development/tests legacy bootstrap), and that
combination is rejected in production. Phase 8's compatibility path for
databases that were created by `create_all` is preserved unchanged in
`alembic_baseline.py` (stamp-head / stamp-0001 decisions), whose docstring
now explains that the startup call was removed.

## 4. 9.3 — Frontend production build

`frontend/src/api/client.ts` resolves the API base URL from
`VITE_API_BASE_URL` through a small, unit-tested helper:

```
VITE_API_BASE_URL set (including empty)  -> used verbatim
   empty   -> same origin: the browser calls /api/v1/... and the
              reverse proxy forwards it to FastAPI
   origin  -> absolute API origin (e.g. https://bfg.example.com)
VITE_API_BASE_URL unset:
   development -> http://localhost:8000   (Vite dev server on :5173)
   production  -> ''                      (same origin behind the proxy)
```

The dashboard's request paths already include the `/api` prefix, so no path
rewriting is needed and the existing API-layer tests are unchanged.

`frontend/vite.config.ts` gained an explicit production build section:
`outDir: dist`, `sourcemap: false`, and vendor chunk splitting for
`react`/`react-dom`/`react-router-dom` and `recharts` — this addresses the
single ~692 kB chunk that Phase 8 flagged.

`frontend/.dockerignore` (new) keeps `node_modules/`, `dist/`, coverage and
`.env` files out of the build context.

## 5. 9.4 — Reverse proxy

`nginx/Dockerfile` is a two-stage image: it builds the dashboard with
`npm ci && npm run build` (Node 22, `VITE_API_BASE_URL` as build arg) and
then serves `dist/` from `nginx:1.27-alpine`, with a self-contained
`/healthz` probe for the container healthcheck.

`nginx/nginx.conf`:

- serves the SPA from `/usr/share/nginx/html` with
  `try_files $uri $uri/ /index.html` for client-side routing;
- proxies `location /api/` to `upstream bfg_api` (`backend:8000`),
  forwarding `Host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`;
- passes `/health` and `/health/ready` through for probe traffic;
- caches hashed static assets for 7 days using `expires` (not `add_header`,
  so the server-level security headers still apply);
- sets baseline security headers: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy`, `server_tokens off`, and a CSP that allows the
  dashboard's own bundle/styles plus the Google Fonts referenced by
  `index.html` (`style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`,
  `font-src 'self' https://fonts.gstatic.com`, `connect-src 'self'`).

`docker-compose.prod.yml` (new) wires the stack together: PostgreSQL keeps
its named volume and healthcheck but publishes **no** port; the backend uses
`expose: 8000` only; only the proxy publishes `${HTTP_PORT:-8080}:80`, and
`POSTGRES_PASSWORD` is mandatory (compose refuses to start without it).

## 6. 9.5 — CORS and API security

- CORS is configuration-driven: the middleware in `app/main.py` is built from
  `settings.cors_origins`. Unset outside production it stays the
  Vite dev origins; configured it is exactly that list; in production an
  explicit list is required and a `*` wildcard is rejected. Credentials are
  automatically disabled when a wildcard is configured.
- A catch-all exception handler returns a fixed
  `{"detail": "Internal server error"}` (HTTP 500) and logs the real
  exception server-side. SQL statements, connection strings, credentials,
  filesystem paths and tracebacks never reach the client. The handler is
  registered on Starlette's server-error path, so tests that deliberately
  surface server exceptions still see them (Phase 8's
  `raise_server_exceptions=False` assertions still receive a 500).
- Development-only behaviour is now environment-gated rather than always on:
  `/docs`, `/redoc` and `/openapi.json` are disabled when
  `APP_ENV=production`.
- No authentication/authorization was added (out of scope for 9.1–9.6).

## 7. 9.6 — Health and readiness

| Endpoint | Meaning | Behaviour |
|---|---|---|
| `GET /health` | liveness | returns `{status, service, version}`; never touches the database |
| `GET /health/ready` | readiness | validates the risk configuration, runs `SELECT 1`, returns 200 `{status: ready, checks: {configuration: ok, database: ok}}`; returns **503** `{status: not_ready, checks: {…: error}, detail: "database unavailable"}` when PostgreSQL is unreachable |

Both live in `app/api/health.py`. The responses are fixed strings, so a
failure never leaks a DSN, credential, path or traceback.

## 8. Deployment steps

```powershell
# 1. Configure the deployment
copy .env.example .env
#    edit .env:
#      APP_ENV=production
#      POSTGRES_PASSWORD=<strong secret>
#      DATABASE_URL=postgresql+psycopg://bfg_user:<secret>@postgres:5432/bruteforceguard
#      CORS_ALLOWED_ORIGINS=https://<your-dashboard-host>   # required in production
#      LOG_LEVEL=INFO

# 2. Build and start
docker compose -f docker-compose.prod.yml up -d --build

# 3. Verify
docker compose -f docker-compose.prod.yml ps
curl http://localhost:8080/health
curl http://localhost:8080/health/ready
curl http://localhost:8080/api/v1/dashboard/summary
# dashboard: http://localhost:8080/
```

Notes:

- Set `HTTP_PORT` to publish the proxy on a different port (default 8080).
- Set `VITE_API_BASE_URL` at build time only when the API lives on a
  different origin; behind the proxy the default (same origin) is correct.
- Schema changes are applied by Alembic: the backend entrypoint runs
  `alembic upgrade head` (or the documented `stamp` + `upgrade`) before
  uvicorn starts. A database created by an older `create_all`-based image is
  detected and stamped correctly, preserving existing data.
- `docker-compose.yml` remains the development stack (it publishes 5432 and
  8000 to the host for local work). It is not the production configuration.

## 9. Tests added for 9.1–9.6

| File | Covers |
|---|---|
| `backend/tests/test_production_config.py` | development defaults, CORS parsing/trimming, wildcard handling, log-level normalization, and every production rejection (unknown env/level, empty URL, missing origins, wildcard, non-PostgreSQL, `CREATE_ALL_ON_STARTUP`) |
| `backend/tests/test_health.py` | `/health` payload and "works while the database is down", `/health/ready` 200 with checks, 503 on database outage, and no leakage of DSN/credentials/tracebacks |
| `backend/tests/test_api_security.py` | configured origin allowed, unconfigured origin refused, preflight behaviour, production origin restriction, generic 500 with no SQL/DSN/path/traceback leakage, 422 stays structured, docs enabled in development and disabled in production |
| `backend/tests/test_deployment_config.py` | production compose invariants (nothing but the proxy publishes a port, PostgreSQL persistent + healthy, mandatory password, proxy waits for a healthy backend), Nginx SPA/API/health proxy rules, security headers, `server_tokens off`, backend non-root + Alembic + healthcheck, `create_all` opt-in, dockerignore coverage |
| `frontend/src/api/client.test.ts` | `resolveApiBaseUrl` for development, production, explicit origin and the empty (same-origin) case |

## 10. Validation status

**All validation checks passed** (2026-09-19).

### Test suites

```powershell
cd backend
python -m pytest -q
# 343 passed, 16 warnings in 124.97s (previous: 298, new: 45 Phase 9 tests)

python -m compileall app tests
# Listing 'app'... (no syntax errors)

cd ..\frontend
npm test
# Test Files  10 passed (10)
# Tests  74 passed (74)
# Duration  44.47s

npm run build
# ✓ 2517 modules transformed
# ✓ built in 3.43s
# dist/index.html                             1.03 kB │ gzip:   0.50 kB
# dist/assets/index-BkGlJBBp.css             24.05 kB │ gzip:   5.31 kB
# dist/assets/rolldown-runtime-hePW80VL.js    0.71 kB │ gzip:   0.42 kB
# dist/assets/index-c5j7au1W.js             109.29 kB │ gzip:  32.71 kB  ← main bundle
# dist/assets/react-Byh070Ur.js             217.53 kB │ gzip:  69.87 kB
# dist/assets/charts-C_cODHJT.js            363.96 kB │ gzip: 105.97 kB
```

### Production deployment

```powershell
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml ps
```

| Service | Status | Ports |
|---|---|---|
| `bruteforceguard-proxy` | Up, healthy | **0.0.0.0:8080→80/tcp** |
| `bruteforceguard-backend` | Up, healthy | 8000/tcp (internal only) |
| `bruteforceguard-postgres` | Up, healthy | 5432/tcp (internal only) |

### Deployment validation

- [x] **Dashboard loads** from `http://localhost:8080/` (React SPA with `id="root"`)
- [x] **`/health` returns 200** with `{"status":"healthy","service":"bruteforceguard-api","version":"0.5.0"}`
- [x] **`/health/ready` returns 200** with `{"status":"ready",...,"checks":{"configuration":"ok","database":"ok"}}`
- [x] **`/health/ready` returns 503** after `docker compose stop postgres` (as required)
- [x] **`/api/v1/dashboard/summary` returns 200** through the proxy (133 events, 17 alerts, 1 session)
- [x] **Port isolation verified**:
  - PostgreSQL (5432): **not reachable** from host ✓
  - Backend (8000): **not reachable** from host ✓
  - Proxy (8080): **reachable** from host ✓
- [x] **CORS behavior correct**:
  - Configured origin (`http://localhost:8080`): **allowed** (`Access-Control-Allow-Origin` present)
  - Unconfigured origin (`https://evil.example.com`): **blocked** (no `Access-Control-Allow-Origin` header)
- [x] **Security headers present**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: no-referrer`, `Content-Security-Policy` with strict defaults, `Server: nginx`
- [x] **Interactive docs disabled in production**: `/docs` through the proxy serves the React SPA (not FastAPI Swagger UI), as intended for client-side routing
- [x] **Backend restart recovery**: `docker compose restart backend` → service returns to healthy within 48 seconds
- [x] **PostgreSQL restart recovery**: `docker compose restart postgres` → service returns to healthy within 9 seconds, readiness check returns 200

**Phase 9.1–9.6 are complete**: implementation, testing, documentation, and deployment validation all passed.

## 11. Remaining Phase 9 work (9.7+)

- 9.7 — TLS termination and HTTPS redirects (certificates, HSTS).
- 9.8 — Authentication/authorization for the API and dashboard.
- 9.9 — Backups and retention for PostgreSQL (restore drill).
- 9.10 — Centralized log aggregation and alerting on `/health/ready`.
- 9.11 — CI pipeline that runs the backend/frontend suites and builds the
  production images.
- 9.12 — Operational runbook (scaling, upgrades, incident recovery).
