# BruteForceGuard

**Authentication threat detection & brute-force monitoring platform.**

BruteForceGuard ingests authentication events (SSH, RDP, web logins, …) from
Linux, Windows, or JSON log sources, detects brute-force and credential abuse
in real time, correlates related events into attack sessions, and presents the
results in an analyst dashboard with risk scoring, MITRE ATT&CK mapping,
RBAC, and a full security audit trail — all self-hosted, with no external
threat-intelligence dependency.

> Version **0.5.0** · Phases 1–9 complete · Backend **541 tests** ✅ ·
> Frontend **152 tests** ✅

---

## Table of contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Detection rules](#detection-rules)
4. [Tech stack](#tech-stack)
5. [Repository layout](#repository-layout)
6. [Quick start](#quick-start)
7. [Configuration](#configuration)
8. [API overview](#api-overview)
9. [Collectors](#collectors)
10. [Testing](#testing)
11. [Documentation](#documentation)
12. [Known limitations & roadmap](#known-limitations--roadmap)

---

## Features

- **6 detection rules** with service-specific thresholds and confidence
  ladders: single-account brute force, password spraying, distributed brute
  force, failed-then-success, credential stuffing, and low-and-slow attacks.
- **Attack-session correlation** — related detections are grouped into
  sessions (create / update / auto-close / expire) with per-type correlation
  keys and evidence.
- **Security intelligence (offline-first)** — deterministic, explainable risk
  scoring; behavioral source reputation from observed history; an
  operator-managed local IOC store; static MITRE ATT&CK mappings. Detection
  keeps working if enrichment fails or is disabled.
- **Alert lifecycle** — dedup/merge, confidence escalation, human-readable
  explanations, triage states (with history), and IP history.
- **Runtime configuration** — engine thresholds/tuning are editable at
  runtime through an admin-only, audited, versioned `PUT /api/v1/config/`
  endpoint with optimistic locking; changes apply to the live engine
  immediately and are re-applied on restart.
- **RBAC & authentication** — interactive login with `admin` / `analyst`
  roles; salted PBKDF2 password hashes; session tokens stored only as
  SHA-256 hashes and revoked on logout / password change / role change /
  deactivation.
- **Security audit log** — every sensitive action is recorded and queryable.
- **IP management** — blocklist/whitelist with HTTP-middleware enforcement.
- **Health & readiness probes**, graceful shutdown, Alembic migrations,
  structured logging, CORS hardening, and a production Docker Compose stack
  behind an Nginx reverse proxy.

## Architecture

```
 collectors (linux / windows / json)          manual / test clients
        │                                              │
        └──────────────┬───────────────────────────────┘
                       ▼
            POST /api/v1/events/          (strict Pydantic validation)
                       │
                       ▼
              PostgreSQL 17  (auth_events)
                       │
                       ▼
        Detection engine (rule registry, 6 detectors,
        runtime-tunable thresholds & windows)
                       │
                       ▼
        Alert engine — dedup/merge, confidence ladders, evidence
                       │
                       ▼
        Correlation → attack sessions (create/update/close/expire)
                       │
                       ▼
        Intelligence enrichment (best-effort):
        reputation + local TI + MITRE + deterministic risk score
                       │
                       ▼
        REST API ──► React dashboard (RBAC-guarded, audited)
```

## Detection rules

| Rule | Default trigger | MITRE | Severity |
|------|-----------------|-------|----------|
| `single_account_bruteforce` | ≥ 5 failures, same IP + user, 300 s | T1110.001 | high |
| `password_spraying` | ≥ 5 users & ≥ 10 failures from one IP, 600 s | T1110.003 | high |
| `distributed_bruteforce` | ≥ 3 IPs & ≥ 10 failures on one user, 600 s | T1110 | high |
| `failed_then_success` | ≥ 3 failures strictly before a success, 300 s | T1110 | critical |
| `credential_stuffing` | ≥ 10 users & ≥ 20 failures from one IP, 600 s | T1110.004 | high |
| `low_and_slow` | ≥ 10 failures, same IP + user, 3600 s, ≥ 5 active intervals | T1110 | medium |

Thresholds are **per-service** (ssh, rdp, web, …), configurable at runtime
via the config API, and mirrored as documentation in
[`detection-rules/`](detection-rules/).

## Tech stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.12 · FastAPI · SQLAlchemy 2 · Alembic · psycopg 3 · pydantic-settings |
| Database | PostgreSQL 17 (production) · in-memory SQLite (test suite) |
| Frontend | React 19 · TypeScript · Vite · Tailwind CSS 4 · React Router 7 · Recharts |
| Tests | pytest (backend) · Vitest + Testing Library (frontend) |
| Deploy | Docker Compose · Nginx reverse proxy (serves SPA, proxies `/api`) |

## Repository layout

```
BruteForceGuard/
├── backend/                  FastAPI application
│   ├── app/
│   │   ├── api/              routers: events, alerts, attack_sessions, auth,
│   │   │                     users, dashboard, health, intelligence, audit,
│   │   │                     config, deps (+ v1/endpoints/blacklist)
│   │   ├── core/             Settings, detection tuning, security, logging
│   │   ├── services/         detection engine, correlation, alert lifecycle,
│   │   │                     explanation, config service, audit, auth
│   │   ├── intelligence/     risk scoring, reputation, local TI, MITRE
│   │   ├── models/           SQLAlchemy models (AuthEvent, Alert,
│   │   │                     AttackSession, User, SecurityAuditLog, …)
│   │   └── schemas/          Pydantic request/response models
│   ├── alembic/versions/     migrations 0001 → 0008
│   └── tests/                541 tests (incl. performance/ & reliability/)
├── frontend/src/
│   ├── pages/                Dashboard, Events, Alerts, Sessions, Analytics,
│   │                         IP Management, Audit Log, Settings
│   ├── components/           alert table & detail panel, session views,
│   │                         intelligence (risk/reputation/MITRE), layout, ui
│   └── api/                  typed API clients
├── collectors/               linux (auth.log), windows (Security log), json
├── detection-rules/          rule YAMLs (documentation source)
├── docs/                     phase 5/7/8/9 reference documents
├── nginx/                    reverse-proxy Dockerfile + config
└── docker-compose[.prod].yml dev / production stacks
```

## Quick start

### Prerequisites

- Docker + Docker Compose **(production / full stack)**, **or**
- Python 3.12, Node.js 20+, and PostgreSQL 17 (local development)

### Development

```powershell
# 1. Environment
cp .env.example .env        # then edit secrets

# 2. Backend
cd backend
..\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
alembic upgrade head        # or: set CREATE_ALL_ON_STARTUP=true (dev only)
uvicorn app.main:app --reload --port 8000

# 3. Frontend (new terminal)
cd frontend
npm install
npm run dev                 # http://localhost:5173
```

Bootstrap the first administrator by setting `AUTH_BOOTSTRAP_ADMIN_USERNAME`
and `AUTH_BOOTSTRAP_ADMIN_PASSWORD` in `.env`; the account is created on the
first API startup.

Minimal stack (database + API) with Docker:

```bash
docker compose up -d --build
```

### Production (Docker Compose)

```bash
cp .env.example .env        # APP_ENV=production, real secrets, CORS origins
docker compose -f docker-compose.prod.yml up -d --build
```

- Only the **Nginx proxy** publishes a port (`HTTP_PORT`, default `8080`);
  PostgreSQL and the backend are reachable only on the internal network.
- The backend image runs `alembic upgrade head` before starting the API.
- Health: `GET /health` (liveness), `GET /health/ready` (readiness — config
  + database).

Full runbooks, backup/restore, migration, and security validation procedures
are in [`docs/phase-9-deployment-productionization.md`](docs/phase-9-deployment-productionization.md).

## Configuration

```bash
cp .env.example .env
```

Key variables (see `.env.example` for the complete reference):

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL`, `POSTGRES_PASSWORD` | PostgreSQL connection (PostgreSQL required in production) |
| `APP_ENV` | `development` / `test` / `staging` / `production` — production enforces strict validation |
| `CORS_ALLOWED_ORIGINS` | Explicit origins required in production (wildcard rejected) |
| `AUTH_BOOTSTRAP_ADMIN_*` | First-run administrator |
| `AUTH_SESSION_TTL_MINUTES` | Login session lifetime (default 480 = 8 h) |
| `ALERT_TRIAGE_API_TOKENS` | Role-bound tokens for alert triage + audit access (fail-closed when unset) |
| `IP_MANAGEMENT_API_TOKENS` | Tokens for blocklist/whitelist writes |
| `RISK_WEIGHTS`, `RISK_LEVEL_BOUNDARIES`, `REPUTATION_LEVEL_BOUNDARIES` | Intelligence tuning |
| `PRIVILEGED_USERS`, `SERVICE_SENSITIVITY` | Risk-model inputs |
| `LOG_LEVEL`, `CREATE_ALL_ON_STARTUP` | Logging / legacy schema bootstrap (rejected in production) |

Detection thresholds themselves live in the database (`system_config`) and
are edited through **Settings → runtime configuration** or
`PUT /api/v1/config/` — not through environment variables.

## API overview

Base path `/api/v1` (interactive docs at `/docs` in development only):

| Area | Endpoints |
|------|-----------|
| Events | `POST/GET /events/`, `GET /events/groups`, `GET /events/{id}` |
| Alerts | `GET /alerts/`, `/stats`, `/{id}`, `/{id}/history`, `PATCH /{id}` |
| Sessions | `GET /attack-sessions/`, `/{id}`, `/stats/active`, `POST /{id}/close` |
| Auth | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` |
| Users (admin) | `GET/POST /users/`, `PATCH /users/{id}` |
| Dashboard | `GET /dashboard/summary`, `GET /dashboard/analytics` |
| Intelligence | `GET /intelligence/ip/{ip}`, `/reputation/{ip}`, `/mitre/{id}`, `/indicators` |
| Audit | `GET /audit/` |
| Config (admin) | `GET/PUT /config/`, `POST /config/reset` |
| Health | `GET /health`, `GET /health/ready` |

## Collectors

Shippers under [`collectors/`](collectors/) share common models/runner/sender:

- **Linux** — parses `auth.log` SSH failures/successes and forwards them.
- **Windows** — parses Security event log authentication entries.
- **JSON** — tails a JSON-lines log file.

Each targets `POST /api/v1/events/` (endpoint + token in `collectors/.env`).

## Testing

```powershell
# Backend — 541 tests, in-memory SQLite (no database needed)
cd backend
..\.venv\Scripts\python.exe -m pytest -q

# Frontend — 152 tests
cd frontend
npm run test -- --run

# Lint + production build
npm run lint
npm run build
```

## Documentation

| Document | Contents |
|----------|----------|
| [`docs/phase-5-validation.md`](docs/phase-5-validation.md) | End-to-end pipeline validation, thresholds, detector tests |
| [`docs/phase-7-security-intelligence.md`](docs/phase-7-security-intelligence.md) | Risk scoring, reputation, TI, MITRE architecture |
| [`docs/phase-8-testing-performance-reliability.md`](docs/phase-8-testing-performance-reliability.md) | Regression, performance benchmarks, reliability |
| [`docs/phase-9-deployment-productionization.md`](docs/phase-9-deployment-productionization.md) | Production deployment, runbooks, backup/restore, acceptance |

## Known limitations & roadmap

Documented in Phase 9; tracked as Phase 10 candidates:

- No CI pipeline yet (tests are run manually — commands above)
- No automated backup scheduling (procedures are documented & validated)
- No TLS termination in-repo (terminate at a load balancer / CDN)
- No dependency vulnerability scanning wired into a pipeline
- No centralized log aggregation (stdout/stderr only)
- Single backend replica (no horizontal-scaling config), no proxy-level
  rate limiting
- **Phase 10 ideas:** Prometheus metrics, alerting integrations
  (webhook/email)

---

*BruteForceGuard is a defensive security tool. Use it only on systems and
logs you are authorized to monitor.*



