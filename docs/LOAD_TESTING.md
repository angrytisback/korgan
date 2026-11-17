# Load testing and audit-path benchmarks

This document records how the audit pipeline (durable outbox + atomic unit of
work, see ADR 0005 and ADR 0009) was measured, the results, and how to repeat
the measurements.

> **Read the caveats.** Everything ran on one 16-core workstation with the load
> generator, Korgan, PostgreSQL 17 and Valkey 8 (Docker, localhost) sharing the
> machine, one run per scenario. Numbers are useful for *comparison between the
> two builds*, not as capacity figures for your hardware.

## 1. HTTP load: before vs after

Builds: `main` before the audit work (in-memory event queue, `try_send`) versus
`agent/03-architecture` (outbox + atomic unit of work), both `--release`.
Setup per build: fresh database, rate limiting disabled
(`KORGAN__RATE_LIMIT__ENABLED=false`), 200 users registered and activated,
default pool sizes, Argon2 defaults.

| Scenario | Before (`main`) | After |
| :--- | ---: | ---: |
| `POST /auth/login`, 30 s, 32 concurrent: throughput | 349 req/s | 363 req/s |
| login p50 / p95 / p99 | 92 / 128 / 151 ms | 87 / 117 / 134 ms |
| successful logins (HTTP 200) | 9 936 | 10 655 |
| `login_success` audit rows written | **2 018** | **10 655** |
| **audit events lost** | **7 918 (≈ 80 %)** | **0** |
| `GET /.well-known/jwks.json`, 10 s, 64 concurrent | 19 286 req/s | 20 394 req/s |
| outbox rows left after the run | n/a | 0 |

After the run the total audit rows were exactly the expected
`10 655 logins + 248 rate-limited logins + 200 registrations = 11 103`, and
`korgan audit verify` reported a valid hash chain.

Why the old build lost events: every successful login queued an audit event on a
1 024-slot in-memory channel that a single worker drained one event at a time
under a global advisory lock (≈ 130 chained events/s). At ≈ 350 logins/s the
channel was permanently full and `try_send` silently discarded the rest.

The login latency is dominated by Argon2 (≈ 85 ms), which hides the cost of the
audit write; section 2 isolates it.

## 2. Database micro-benchmark (audit paths)

`tests/real_db.rs::bench_audit_paths` (debug-built test, real PostgreSQL 17 in
Docker on localhost, so a commit costs ≈ 4.5 ms of fsync).

| Operation | concurrency 1 | concurrency 16 |
| :--- | :--- | :--- |
| legacy `append_and_chain` (lock + chain per event) | 129 ops/s, p50 7.4 ms | 133 ops/s, p50 122 ms |
| outbox `enqueue` (what a request now pays) | 208 ops/s, p50 4.5 ms | 515 ops/s, p50 29 ms |
| create user, no audit | 190 ops/s, p50 4.7 ms | 550 ops/s, p50 28 ms |
| create user + atomic audit (`audited`) | 168 ops/s, p50 6.1 ms | 553 ops/s, p50 28 ms |

* The legacy path is serialized by the global advisory lock: throughput stays at
  ≈ 130 events/s however many requests arrive.
* `enqueue` is lock-free and scales with concurrency.
* Making a state change atomic with its audit entry costs ≈ 1.4 ms of latency
  for a single sequential caller (one extra INSERT in the same transaction) and
  is within noise at 16 concurrent callers.
* Chaining happens in the background: one drainer moved 4 800 queued entries into
  the hash chain in 0.81 s (≈ 5 960 entries/s, batch 200), roughly 45× the legacy
  ceiling. Several replicas can drain; they serialize on the same advisory lock.

## 3. Reproducing

```bash
# 1. PostgreSQL 17 and Valkey/Redis on free ports (do not reuse a database you care about)
docker run -d --name kg-pg -e POSTGRES_USER=korgan -e POSTGRES_PASSWORD=bench \
  -p 127.0.0.1:55432:5432 postgres:17-alpine
docker run -d --name kg-redis -p 127.0.0.1:56379:6379 valkey/valkey:8-alpine

# 2. Micro-benchmark (creates and drops its own database)
KORGAN_TEST_DATABASE_URL=postgres://korgan:bench@127.0.0.1:55432/postgres \
  cargo test --release --test real_db bench_audit_paths -- --ignored --nocapture

# 3. HTTP load against a release build
cargo build --release
export DATABASE_URL=postgres://korgan:bench@127.0.0.1:55432/korgan_load \
       REDIS_URL=redis://127.0.0.1:56379 \
       KORGAN__RATE_LIMIT__ENABLED=false KORGAN__HIBP__ENABLED=false \
       KORGAN__SERVER__PORT=18080 KORGAN__SERVER__HOST=127.0.0.1
# (also set KORGAN__CRYPTO__ED25519_PRIVATE_KEY_PEM and KORGAN__CRYPTO__AES_MASTER_KEY)
docker exec kg-pg psql -U korgan -d postgres -c "CREATE DATABASE korgan_load"
target/release/korgan serve &
pip install aiohttp
python3 scripts/loadtest.py http://127.0.0.1:18080 register 200
docker exec kg-pg psql -U korgan -d korgan_load \
  -c "UPDATE users SET status='active', email_verified_at=now() WHERE email LIKE 'load%'"
python3 scripts/loadtest.py http://127.0.0.1:18080 login 200 30 32
python3 scripts/loadtest.py http://127.0.0.1:18080 get /.well-known/jwks.json 10 64
# afterwards: login_success rows must equal the number of HTTP 200 logins
docker exec kg-pg psql -U korgan -d korgan_load \
  -c "SELECT count(*) FROM audit_logs WHERE event_type='login_success'" \
  -c "SELECT count(*) FROM audit_outbox"
```

## 4. Not measured

* Multi-replica behaviour under load (correctness with two replicas is covered by `two_replicas_drain_one_outbox_...` in `tests/real_db.rs`).
* Sustained multi-hour soak, memory growth, connection-pool saturation behaviour.
* Production-like PostgreSQL (replication, remote storage) and network latency.
* Variance between runs (one run per scenario).
