# Phase 8 — Testing, Performance & Reliability

Phase 8 froze the Phase 7 architecture and validated the complete
BruteForceGuard pipeline — event validation, detection, correlation,
attack-session management, security intelligence, alerting, REST API and
dashboard — under normal traffic, attacks, failures, restarts and larger
datasets. No architectural redesign was performed; the guiding principle
was **measure first, fix real problems, don't redesign working
architecture**.

## 1. Regression Testing (Phases 1–7)

Full backend suite against the frozen Phase 7 codebase:

```
pytest -q
298 passed, 16 warnings in 54.56s
```

Suite coverage by area (all previously existing tests preserved, none
skipped to make the phase pass):

- **Event ingestion**: valid/failed/successful events, malformed payloads,
  missing source IP, invalid timestamp/service/username/outcome
  (`extra="forbid"` Pydantic schemas, IPvAnyAddress validation).
- **Detection**: single-account brute force, password spray, distributed
  brute force, failed-then-success, credential stuffing, low-and-slow —
  including detection type, severity, confidence, evidence and threshold
  behavior.
- **Correlation**: same-attack correlation and non-correlation across
  accounts, services, source IPs and time windows.
- **Sessions**: creation, reuse, closure, expiration, statistics, evidence
  and detection types.
- **Intelligence (Phase 7)**: risk score/level/factors, reputation,
  threat-intelligence lookup, MITRE mapping, behavioral profile.
- **APIs**: `/events`, `/alerts`, `/alerts/{id}`, `/attack-sessions`,
  `/dashboard/summary`, `/intelligence/*` — 200/404/422 responses and
  response schemas.

Phase 5 regression is explicitly covered by dedicated tests proving the
`event -> detection -> alert -> session` chain still produces the expected
results, and that Phase 7 enrichment enriches detection evidence without
replacing it.

```
python -m compileall app tests alembic_baseline.py
EXIT_CODE=0
```

Frontend regression:

```
npx vitest run
Test Files  9 passed (9) | Tests  69 passed (69)
```

(Phase 7 baseline: 8 files / 64 tests. Phase 8 added
`RiskFactors.test.tsx` and hardened `SessionDetails.test.tsx` /
`fixtures.ts`.)

Frontend production build: PASS (`npm run build`, 48.77s).

## 2. Database Migration & Recovery Testing

Verified against Alembic migrations on temporary databases (SQLite
compiled-dialects, per `tests/test_migrations.py`) and against the live
Docker PostgreSQL 17 volume:

- **Fresh database** — `alembic upgrade head` produces the full Phase 7
  schema (`0001_phase6_base` -> `0002_phase7_intelligence` -> head); columns
  match the SQLAlchemy models exactly.
- **Existing Phase 6 database** — additive upgrade preserves existing
  events, alerts and sessions with unchanged IDs; new columns take their
  safe server defaults (`risk_score=0`, `risk_level='informational'`).
- **create_all databases** — the documented stamp procedure works, and
  Phase 8 extended it (see Fix Log) for databases already at the Phase 7
  schema.

## 3. Constraint, Transaction and Duplicate Testing

- Database constraints reject out-of-range confidence (0 / 101), invalid
  indicator types, malformed IPs and malformed usernames (validated at the
  schema/service boundaries; tests assert clean rejection).
- Transaction/rollback tests simulate mid-pipeline failures (e.g. alert
  creation raising after event insert) and verify no partially-created

## 4. Intelligence Failure Testing (Phase 7 best-effort guarantee)

A `FailingProvider` is injected so `lookup_ip()` (and the username lookup,
reputation calculation, MITRE lookup and malformed-TI-data paths) raise.
Verified for each:

```
TI fails -> warning logged -> detection continues
        -> alert still created -> session still processed
```

A TI failure never converts into a detection failure
(`tests/reliability/test_provider_failure.py`).

## 5. Database Failure & Restart Testing (live Docker stack)

- **PostgreSQL restart** (`docker compose restart postgres`): the backend
  recovered immediately — `GET /api/v1/dashboard/summary` returned 200 on
  the first post-restart request and again 30 s later; `docker compose ps`
  showed postgres healthy again.
- **Backend restart** (`docker compose restart backend`): API returned 200
  after restart; the entrypoint migration step ran cleanly.
- **Database unavailability** is handled gracefully by the reliability
  tests (`tests/reliability/test_database_failure.py`,
  `tests/reliability/test_recovery.py`): operations fail cleanly rather
  than hanging indefinitely, and processing resumes after recovery.
- **Restart recovery**: all alerts, sessions, events and intelligence data

## 7. Performance Benchmarks

Measured values (detection throughput, ingestion throughput, intelligence
overhead, API latency by dataset size, 11k-event large dataset) are
recorded in `docs/performance/phase-8-benchmark-results.md`. Key results:

- Detection: 7.0 ms/event (1k) -> 10.9 ms/event (5k), all six detectors.
- Full-pipeline ingestion: 13.7 ms/event on an empty DB; 29.7 ms/event over
  a 10k+ dataset (33.6 events/s), zero errors.
- Phase 7 intelligence overhead: ~5 ms per alerted event — not a bottleneck.
- API latency: list endpoints flat across dataset sizes;
  `dashboard/summary` grows with the event table (299 ms at 11k events),
  documented as the first optimization candidate if datasets grow beyond
  ~50k events.
- N+1 review: intelligence service and repositories were inspected; the
  per-alert overhead (~5 ms) does not justify introducing a cache layer.
  No premature infrastructure (Redis/Kafka/etc.) was added.
- Frontend: 69 tests pass; large-table behavior verified against 100/1,000
  alert datasets with no severe rendering delays or broken pagination.

## 8. Logging & Error-Handling Review

- No `print()` statements in backend `app/` code.
- No secrets logged: reviewed log statements emit IDs, IPs, usernames and
  results only — never passwords, tokens, API keys or database credentials.
- `except Exception` appears only in the two intentionally defensive
  places: `app/api/events.py` (detector isolation — ingestion must not
  fail because one detector failed) and `app/intelligence/service.py`
  (best-effort TI per Phase 7). Both log warnings; neither silently
  swallows the failure.
- Broad `except: pass` patterns: none.

## 9. Security Regression

- Input validation: all external input passes Pydantic schemas
  (`extra="forbid"`, `IPvAnyAddress`, bounded string lengths, port range).
- SQL injection: SQLAlchemy ORM/`select()` constructs throughout; no string
  concatenation into SQL.
- Secrets: `git ls-files` shows only `.env.example`; the real `.env`, keys
  and PEM files are untracked. Secret-name greps over `*.py` surface only
  legitimate regex constants in the SSH auth parser
  (`FAILED_PASSWORD`/`ACCEPTED_PASSWORD`).
- CORS: restricted to the Vite dev-server origins
  (`http://localhost:5173`, `http://127.0.0.1:5173`), with an explicit
  comment that production deployments should restrict further.
- No development/debug endpoints or debug flags enabled in the production
  configuration path.

  survive backend and database restarts; the dashboard remains functional
  (verified against the live stack, 133 events / 17 alerts preserved).

## 6. Concurrency Testing

Concurrent event ingestion (100 events across 10 source IPs, 5 usernames,
3 services) was exercised via the API layer: no race conditions, duplicate
sessions, duplicate alerts, integrity errors, incorrect counters or
inconsistent risk scores were observed.

  alerts, corrupted sessions, orphan records or inconsistent relationships
  remain.
- Duplicate-event behavior was tested against the existing design: exact
  duplicate events are treated as separate authentication attempts (the
  system's intended semantics); tests verify duplicates do not create
  unrelated attack sessions beyond the documented correlation rules. No
  semantics were changed to make tests pass.

## 10. End-to-End Validation (live stack)

A realistic attack sequence was replayed over HTTP against the running
Docker Compose stack (PostgreSQL 17 + backend):

```
6 x failed login (203.0.113.77 -> e2e_victim via ssh)
1 x successful login
```

Verified full-pipeline behavior:

| Stage                  | Result                                                        |
|------------------------|---------------------------------------------------------------|
| Event ingestion        | 7 events accepted (ids 127–133), 200 per request              |
| Detection              | alert 16 `single_account_bruteforce` (high/50, T1110.001)     |
|                        | alert 17 `failed_then_success` (critical/80, T1110)           |
| Risk enrichment        | 48/low and 60/medium with full risk-factor breakdowns         |
| Attack session         | session 13 correlated both detections, source IP, username    |
| MITRE                  | T1110 / T1110.001 mapped on both alerts                       |
| Dashboard              | 133 events / 17 alerts reflected immediately                  |
| Intelligence API       | consistent `known=false` response for the attacker IP         |

### Data consistency (DB vs API)

Values compared directly between PostgreSQL and the REST API:

| Field                | PostgreSQL (alerts) | API (alerts/17, alerts/16) | Match |
|----------------------|---------------------|----------------------------|-------|
| alert 17 type/severity | `failed_then_success`/`critical` | identical | OK |
| alert 17 confidence/risk | 80 / 60 (medium) | identical | OK |
| alert 17 MITRE/status | T1110 / open | identical | OK |
| alert 16 type/severity | `single_account_bruteforce`/`high` | identical | OK |
| alert 16 confidence/risk | 50 / 48 (low) | identical | OK |
| session 13 type/severity | `single_account`/`critical` | identical | OK |

## 11. Fix Log (real problems found and fixed)

1. **`frontend/src/components/intelligence/RiskFactors.tsx`** — component
   crashed on null/missing risk factors (API returns `risk_factors: []`
   or partial factors); hardened rendering + added
   `RiskFactors.test.tsx` (frontend now 69 tests).
2. **`backend/alembic_baseline.py` + `backend/Dockerfile` entrypoint** —
   databases created by `create_all` at the Phase 7 schema failed to start
   under Alembic (`DuplicateColumn`). The entrypoint now detects
   create_all-managed databases and stamps the matching baseline (or head)
   before upgrading, preserving the documented stamp procedure from the
   migration plan.
3. **`backend/tests/test_migrations.py`** — added 5 regression tests
   covering the create_all-at-head stamp path (293 -> 298 backend tests).
4. **Repository hygiene** — 5 stale tracked artifacts removed
   (`_process_err.txt`, `_pwd_test.txt`, `_run_tests.bat`, etc.) and
   `.gitignore` hardened so generated test output cannot return.

## 12. Phase 8 Acceptance Criteria

### Functional

- [x] Backend tests pass (298 passed)
- [x] Frontend tests pass (69 passed, 9 files)
- [x] Python compilation passes (`EXIT_CODE=0`)
- [x] Frontend production build passes
- [x] Phase 5 regression passes (dedicated pipeline regression tests)
- [x] Phase 6 regression passes (dashboard/API/session tests)
- [x] Phase 7 regression passes (intelligence tests + reliability failure tests)

### Database

- [x] Fresh migration works (`upgrade head` on empty DB)
- [x] Existing Phase 6 database upgrades with data preserved
- [x] Existing data / IDs preserved through upgrades
- [x] Database constraints work (confidence range, indicator type, IP, username)
- [x] Rollback/error handling tested (no orphans / partial alerts)

### Reliability

- [x] TI failure doesn't break detection
- [x] Reputation failure doesn't break detection
- [x] MITRE failure doesn't break detection
- [x] Backend restart works (live Docker)
- [x] PostgreSQL restart works (live Docker)
- [x] Docker restart works (`restart backend` / `restart postgres`)
- [x] API failures handled correctly (404/422/clean error handling tested)

### Performance

- [x] Event throughput measured (detection + full pipeline)
- [x] API performance measured (10/100/1,000 records + 10k dataset)
- [x] Intelligence overhead measured (~5 ms/alert)
- [x] Large dataset tested (11k+ events)
- [x] Memory/CPU behavior reviewed (no growth symptoms; noted in benchmarks)
- [x] N+1/unnecessary queries reviewed (no cache layer justified)

### Security

- [x] No secrets committed (only `.env.example` tracked)
- [x] No secrets logged
- [x] Input validation tested (schemas reject malformed input cleanly)
- [x] SQL access reviewed (SQLAlchemy ORM only)
- [x] Development-only endpoints clearly identified (none beyond `/health`)
- [x] Debug artifacts removed (5 stale files removed; .gitignore hardened)

### Documentation

- [x] Phase 8 documentation created (this file)
- [x] Benchmark results recorded (`docs/performance/phase-8-benchmark-results.md`)
- [x] Reliability results recorded (both docs)
- [x] Known limitations documented (benchmark doc, Remaining Limitations)
- [x] README updated if necessary (not required — no user-facing behavior changed)

### Repository

`git status` contains only intentional Phase 8 work; no temporary output
files, coverage artifacts or debug scripts remain.

## 13. Known Limitations & Future Candidates

- `GET /dashboard/summary` aggregates over the whole event table
  (299 ms at 11k events); revisit beyond ~50k events.
- Detection per-event cost grows mildly with dataset size (time-bounded
  window queries); fine at this scale.
- Single 692 kB frontend chunk (207 kB gzipped); revisit if the bundle grows.
- Benchmarks were taken on SQLite test databases on a low-power CPU;
  absolute production-PostgreSQL numbers will differ (trends are the
  validated signal).

| session 13 events/status | 2 / active | identical | OK |
| session 13 correlation | IPs=[203.0.113.77], users=[e2e_victim], detections=[single_account, failed_success] | identical | OK |

The backend remains authoritative; the frontend renders values served by
the API and does not independently compute security-critical values.

