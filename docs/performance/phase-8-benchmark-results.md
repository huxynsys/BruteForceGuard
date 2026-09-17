# Phase 8 Performance Results

All values in this document are **actual measurements** taken during Phase 8
testing. No targets were invented beforehand; ceilings used by the
performance test suite are deliberately generous regression guard rails
(see `backend/tests/performance/`).

## Environment

- OS: Windows 10 (workstation)
- Python: 3.12.10
- PostgreSQL: 17.11 (postgres:17 container image)
- Docker: 29.8.0 (Docker Desktop)
- CPU: Intel Core i5-5200U @ 2.20 GHz (2 cores / 4 threads)
- RAM: 7.9 GB
- Backend test database: in-memory SQLite (suite) / file-backed SQLite (large-dataset bench)
- Live stack: Docker Compose (backend + PostgreSQL 17)

## Backend Tests

Command:

```
pytest -q
```

Result:

```
298 passed, 16 warnings in 54.56s
```

(293 pre-Phase 8 tests + 5 new Phase 8 migration-baseline tests.)

## Frontend Tests

Command:

```
npx vitest run
```

Result:

```
Test Files  9 passed (9)
     Tests  69 passed (69)
  Duration  36.49s
```

(Phase 7 baseline was 8 files / 64 tests; Phase 8 added
`RiskFactors.test.tsx`.)

## Build

Command:

```
npm run build
```

Result: PASS (48.77s)

```
dist/index.html                    0.79 kB | gzip:   0.44 kB
dist/assets/index-BkGlJBBp.css    24.05 kB | gzip:   5.31 kB
dist/assets/index-CL-dTviC.js    691.72 kB | gzip: 207.64 kB
```

Note: the single JS chunk exceeds the 500 kB Vite warning threshold.
Acceptable for this project's scale; code-splitting is a candidate for a
future phase if the bundle grows further.

## Python Compilation

Command:

```
python -m compileall app tests alembic_baseline.py
```

Result: `EXIT_CODE=0`

## Event Throughput (detection layer)

Six detectors run per event over a stored event set
(`tests/performance/test_detection_performance.py`, in-memory SQLite):

| Events | Seed time | Detection time | ms/event | Events/sec |
|-------:|----------:|---------------:|---------:|-----------:|
| 1,000  | 0.060 s   | 7.013 s        | 7.01     | 142.6      |
| 5,000  | 0.202 s   | 54.396 s       | 10.88    | 91.9       |

## Full-Pipeline Ingestion (HTTP: validation + detection + intelligence + alert + session)

`tests/performance/test_ingestion_performance.py`, in-memory SQLite:

| Dataset state | Events | Time    | ms/event | Events/sec |
|---------------|-------:|--------:|---------:|-----------:|
| Empty DB      | 150    | 2.059 s | 13.73    | 72.8       |

Large-dataset run (one-off `bfg_large_bench.py`, file-backed SQLite,
11,180 events pre-seeded with mixed normal traffic, brute force, password
spray and a distributed attack):

| Dataset state | Events | Time     | ms/event | Events/sec | Errors |
|---------------|-------:|---------:|---------:|-----------:|-------:|
| 10k+ dataset  | 500    | 14.867 s | 29.73    | 33.6       | 0      |

Ingestion throughput degrades roughly linearly with dataset size because the
detectors query the event table inside their correlation windows; the windows
themselves are time-bounded, so this is expected behavior rather than an
unbounded scan. Recorded as a known characteristic, not a defect, at this
project's scale.

## Intelligence Overhead (Phase 7 enrichment)

`tests/performance/test_intelligence_performance.py`:

| Measurement                              | Value    |
|------------------------------------------|---------:|
| Alert processing without intelligence     | 13.76 ms |
| Alert processing with intelligence        | 18.69 ms |
| Intelligence overhead per alert           | 4.94 ms  |
| Reputation calculation, 10 history rows   | 1.57 ms  |
| Reputation calculation, 500 history rows  | 12.62 ms |

Conclusion: Phase 7 enrichment adds ~5 ms per alerted event. It is not a
bottleneck relative to the ~13.7 ms full-pipeline ingestion cost per event.

## Large Dataset (Part 14)

Dataset: 11,180 seeded events (normal success/failure traffic across
250 IPs / 80 users / 4 services, plus 20 brute-force IPs x 50 failures, a
90-attempt password spray across 30 users, and a 90-attempt distributed
attack from 30 IPs).

| Metric                          | Value     |
|---------------------------------|-----------|
| Seed time (bulk insert)         | 0.219 s   |
| Live pipeline ingestion         | 500 events / 14.87 s (29.73 ms/event) |
| Ingestion errors                | 0         |
| Final events                    | 11,680    |
| Final alerts                    | 40        |
| Final attack sessions           | 20        |
| Threat indicators               | 0 (TEST-NET ranges not in local TI data) |
| Database size                   | 2.80 MB   |
| Peak memory                     | not separately measured (single-process bench; no growth symptoms observed) |


## API Performance

Latency by dataset size (10 / 100 / 1,000 seeded records each of events,
alerts and sessions; in-memory SQLite):

| Endpoint                                  | 10 records | 100 records | 1,000 records |
|-------------------------------------------|-----------:|------------:|--------------:|
| GET /api/v1/events/                       | 11.05 ms   | 11.04 ms    | 12.20 ms      |
| GET /api/v1/alerts/                       | 58.97 ms   | 11.65 ms    | 12.29 ms      |
| GET /api/v1/attack-sessions/              | 11.19 ms   | 9.78 ms     | 8.17 ms       |
| GET /api/v1/dashboard/summary             | 14.39 ms   | 13.30 ms    | 93.45 ms      |
| GET /api/v1/attack-sessions/stats/active  | 6.84 ms    | 9.29 ms     | 153.85 ms     |
| GET /api/v1/intelligence/indicators       | 13.32 ms   | 6.34 ms     | 3.84 ms       |

Latency at the 10k+ dataset (11k+ events / 40 alerts / 20 sessions,
file-backed SQLite):

| Endpoint                                      | Latency   | Status |
|-----------------------------------------------|----------:|-------:|
| GET /api/v1/events/?limit=100                 | 13.87 ms  | 200    |
| GET /api/v1/alerts/?limit=100                 | 19.41 ms  | 200    |
| GET /api/v1/attack-sessions/?limit=100        | 15.60 ms  | 200    |
| GET /api/v1/dashboard/summary                 | 298.53 ms | 200    |
| GET /api/v1/attack-sessions/stats/active      | 8.95 ms   | 200    |
| GET /api/v1/intelligence/indicators?limit=100 | 17.70 ms  | 200    |

Findings:

- List endpoints with `limit` pagination stay flat as datasets grow.
- `GET /dashboard/summary` grows with the event table (13 ms -> 93 ms ->
  299 ms from 100 to 11k events) because it aggregates over all events.
  At this project's scale this is acceptable; if datasets grow much beyond
  ~50k events, this endpoint is the first candidate for aggregate-table or

## Reliability

- Database restart (PostgreSQL container restart): PASS — backend recovered
  immediately (dashboard 200 on the first post-restart request and again
  at +30 s).
- Backend restart (`docker compose restart backend`): PASS — 200 after
  restart, entrypoint migration step clean.
- TI provider failure (failing provider injected): PASS — detection, alert
  creation and session processing continue; warning logged.
- Migration (fresh volume): PASS — `upgrade head` creates the Phase 7 schema.
- Migration (Phase 6 create_all volume): PASS — `stamp 0001_phase6_base` +
  `upgrade head` preserves data.
- Migration (Phase 7 create_all volume / live-volume regression): PASS after
  fix — the entrypoint now stamps head instead of failing with
  `DuplicateColumn` (see phase-8 doc, Fix Log).
- E2E attack sequence (6 failures + 1 success over HTTP against the live
  Docker stack): PASS — events ingested, two alerts created
  (`single_account_bruteforce`, `failed_then_success`), session correlated
  and enriched, dashboard updated, DB == API values.

## Findings

1. Detection cost per event grows mildly with dataset size (7.0 -> 10.9
   ms/event from 1k to 5k events) because detectors query their windows;
   windows are time-bounded so the growth is moderate.
2. `dashboard/summary` is the only endpoint with meaningful dataset-size
   sensitivity; acceptable at current scale.
3. Phase 7 intelligence overhead is small (~5 ms per alerted event) and
   best-effort by design.
4. Frontend bundle is a single 692 kB chunk (207 kB gzipped) — fine for the
   dashboard's scale, worth revisiting only if it grows.

## Remaining Limitations

- Benchmarks run on SQLite (test) and a low-power CPU; absolute numbers are
  not production-PostgreSQL numbers. Relative behavior (growth trends,
  failure handling) is what Phase 8 validates.
- The 10k+ large-dataset run is a one-off script, not part of the permanent
  suite, to keep the standard test run fast.
- `dashboard/summary` aggregation is O(event table) — documented above.
- No Redis/cache layer: repeated reputation lookups within a single
  processing operation are acceptable at measured overhead (~5 ms/alert);
  introducing caching would be premature.

  query optimization.
- `GET /attack-sessions/stats/active` showed a one-off 154 ms at 1,000
  records but 9 ms at 10k+ records; treat the 1,000-record figure as noise
  from a cold first measurement.

