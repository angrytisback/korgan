//! Tests against a real PostgreSQL server.
//!
//! They are `#[ignore]`d so a plain `cargo test` never silently "passes"
//! without a database. Run them with:
//!
//! ```text
//! KORGAN_TEST_DATABASE_URL=postgres://user:pass@localhost:5432/postgres \
//!     cargo test --test real_db -- --ignored
//! ```
//!
//! The URL must point at a server where the user may `CREATE DATABASE`; every
//! test works in its own throw-away database.

use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TestDb {
    pool: PgPool,
    admin_url: String,
    name: String,
}

impl TestDb {
    async fn create() -> Result<Self, Box<dyn std::error::Error>> {
        let admin_url = std::env::var("KORGAN_TEST_DATABASE_URL")
            .map_err(|_| "KORGAN_TEST_DATABASE_URL is not set")?;
        let name = format!("korgan_test_{}", Uuid::new_v4().simple());
        let mut admin = PgConnection::connect(&admin_url).await?;
        // SAFE: `name` is "korgan_test_" + a UUID in hex; no external input.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut admin)
            .await?;
        admin.close().await?;

        let (base, _) = admin_url
            .rsplit_once('/')
            .ok_or("KORGAN_TEST_DATABASE_URL has no database component")?;
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&format!("{base}/{name}"))
            .await?;
        Ok(Self {
            pool,
            admin_url,
            name,
        })
    }

    async fn drop_db(self) -> TestResult {
        self.pool.close().await;
        let mut admin = PgConnection::connect(&self.admin_url).await?;
        // SAFE: see `create`.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {} WITH (FORCE)",
            self.name
        )))
        .execute(&mut admin)
        .await?;
        Ok(())
    }
}

async fn table_exists(pool: &PgPool, table: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("public.{table}"))
        .fetch_one(pool)
        .await
}

#[tokio::test]
#[ignore = "needs KORGAN_TEST_DATABASE_URL"]
async fn embedded_migrations_apply_to_an_empty_database_and_are_idempotent() -> TestResult {
    let db = TestDb::create().await?;

    korgan::bootstrap::run_migrations(&db.pool).await?;
    for table in ["users", "sessions", "audit_logs", "passkeys"] {
        assert!(table_exists(&db.pool, table).await?, "{table} missing");
    }

    // A second run is a no-op.
    korgan::bootstrap::run_migrations(&db.pool).await?;
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&db.pool)
        .await?;
    assert_eq!(
        applied as usize,
        korgan::bootstrap::MIGRATOR.migrations.len()
    );

    db.drop_db().await
}

#[tokio::test]
#[ignore = "needs KORGAN_TEST_DATABASE_URL"]
async fn concurrent_migration_runs_are_serialized_by_the_advisory_lock() -> TestResult {
    let db = TestDb::create().await?;

    // Several replicas booting at once must all succeed (HA rollout).
    let runs: Vec<_> = (0..4)
        .map(|_| {
            let pool = db.pool.clone();
            tokio::spawn(async move { korgan::bootstrap::run_migrations(&pool).await })
        })
        .collect();
    for run in runs {
        run.await??;
    }
    assert!(table_exists(&db.pool, "users").await?);

    db.drop_db().await
}

// ---------------------------------------------------------------------------
// Audit outbox
// ---------------------------------------------------------------------------

use korgan::adapters::outbound::postgres::PostgresAuditLogRepository;
use korgan::domain::entities::{AuditEventStatus, AuditLog};
use korgan::domain::value_objects::RequestId;
use korgan::ports::repositories::{AuditLogRepository, AuditOutbox};

fn entry(n: u32) -> AuditLog {
    AuditLog::new(
        None,
        None,
        None,
        RequestId::new(),
        "outbox.test",
        AuditEventStatus::Success,
        serde_json::json!({ "n": n }),
    )
}

/// The chain must start at genesis and every entry must link to its predecessor.
async fn assert_chain_valid(repo: &PostgresAuditLogRepository, expected: usize) -> TestResult {
    let all = repo.list_all_chronological().await?;
    assert_eq!(all.len(), expected, "unexpected number of chained entries");
    let mut prev: Option<String> = None;
    for item in &all {
        assert!(
            item.verify_integrity(prev.as_deref()),
            "chain broken at {}",
            item.id
        );
        prev = item.entry_hash.clone();
    }
    Ok(())
}

#[tokio::test]
#[ignore = "needs KORGAN_TEST_DATABASE_URL"]
async fn outbox_chains_every_entry_exactly_once_under_concurrency() -> TestResult {
    let db = TestDb::create().await?;
    korgan::bootstrap::run_migrations(&db.pool).await?;
    let repo = std::sync::Arc::new(PostgresAuditLogRepository::new(db.pool.clone()));

    // 6 producers x 10 entries, racing with 4 drainers.
    let producers: Vec<_> = (0..6u32)
        .map(|p| {
            let repo = repo.clone();
            tokio::spawn(async move {
                for i in 0..10u32 {
                    repo.enqueue(&entry(p * 10 + i)).await?;
                }
                Ok::<(), korgan::ports::errors::PortError>(())
            })
        })
        .collect();
    let drainers: Vec<_> = (0..4)
        .map(|_| {
            let repo = repo.clone();
            tokio::spawn(async move {
                for _ in 0..40 {
                    repo.drain(7).await?;
                    tokio::task::yield_now().await;
                }
                Ok::<(), korgan::ports::errors::PortError>(())
            })
        })
        .collect();
    for task in producers {
        task.await??;
    }
    for task in drainers {
        task.await??;
    }
    while repo.pending().await? > 0 {
        repo.drain(50).await?;
    }

    assert_eq!(repo.pending().await?, 0);
    assert_chain_valid(&repo, 60).await?;
    let distinct: i64 = sqlx::query_scalar("SELECT count(DISTINCT id) FROM audit_logs")
        .fetch_one(&db.pool)
        .await?;
    assert_eq!(distinct, 60, "an entry was chained twice or lost");

    db.drop_db().await
}

#[tokio::test]
#[ignore = "needs KORGAN_TEST_DATABASE_URL"]
async fn outbox_entries_survive_a_restart_and_extend_an_existing_chain() -> TestResult {
    let db = TestDb::create().await?;
    korgan::bootstrap::run_migrations(&db.pool).await?;

    // Existing chain written through the classic path.
    let classic = PostgresAuditLogRepository::new(db.pool.clone());
    let mut first = entry(0);
    classic.append_and_chain(&mut first).await?;

    // "Process A" enqueues and dies before draining; nothing is held in memory.
    {
        let repo_a = PostgresAuditLogRepository::new(db.pool.clone());
        repo_a.enqueue(&entry(1)).await?;
        repo_a.enqueue(&entry(2)).await?;
    }

    // "Process B" finds the queued entries and appends them to the chain.
    let repo_b = PostgresAuditLogRepository::new(db.pool.clone());
    assert_eq!(repo_b.pending().await?, 2);
    assert_eq!(repo_b.drain(100).await?, 2);
    assert_eq!(
        repo_b.drain(100).await?,
        0,
        "drain must be a no-op once empty"
    );
    assert_chain_valid(&repo_b, 3).await?;

    db.drop_db().await
}

#[tokio::test]
#[ignore = "needs KORGAN_TEST_DATABASE_URL"]
async fn malformed_outbox_rows_are_quarantined_and_do_not_block_the_queue() -> TestResult {
    let db = TestDb::create().await?;
    korgan::bootstrap::run_migrations(&db.pool).await?;
    let repo = PostgresAuditLogRepository::new(db.pool.clone());

    sqlx::query("INSERT INTO audit_outbox (payload) VALUES ($1)")
        .bind(serde_json::json!({ "not": "an audit entry" }))
        .execute(&db.pool)
        .await?;
    repo.enqueue(&entry(1)).await?;

    assert_eq!(
        repo.drain(10).await?,
        1,
        "the valid entry must still be chained"
    );
    assert_eq!(repo.pending().await?, 0);
    let quarantined: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_outbox WHERE quarantined_at IS NOT NULL")
            .fetch_one(&db.pool)
            .await?;
    assert_eq!(
        quarantined, 1,
        "the malformed row must be kept, not deleted"
    );
    assert_chain_valid(&repo, 1).await?;

    db.drop_db().await
}

#[tokio::test]
#[ignore = "needs KORGAN_TEST_DATABASE_URL"]
async fn event_bus_and_worker_deliver_audit_events_end_to_end() -> TestResult {
    use korgan::adapters::outbound::mail::ConsoleMailProvider;
    use korgan::application::workers::{EventBus, EventWorker};

    let db = TestDb::create().await?;
    korgan::bootstrap::run_migrations(&db.pool).await?;
    let repo = std::sync::Arc::new(PostgresAuditLogRepository::new(db.pool.clone()));

    // A queue of capacity 1 would drop almost everything without the outbox.
    let (bus, rx) = EventBus::new(1);
    let bus = bus.with_audit_outbox(repo.clone());
    let worker = EventWorker::new(
        rx,
        std::sync::Arc::new(ConsoleMailProvider::new("noreply@example.test")),
        repo.clone(),
        "https://example.test".to_owned(),
    )
    .with_audit_outbox(
        repo.clone(),
        bus.audit_outbox_wake(),
        25,
        std::time::Duration::from_millis(200),
    );
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(worker.run(stop_rx));

    let producers: Vec<_> = (0..5u32)
        .map(|p| {
            let bus = bus.clone();
            tokio::spawn(async move {
                for i in 0..10u32 {
                    bus.record_audit(entry(p * 10 + i)).await;
                }
            })
        })
        .collect();
    for task in producers {
        task.await?;
    }

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if repo.count_all().await.unwrap_or(0) == 50 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| "audit entries were not all chained in time")?;

    stop_tx.send(true)?;
    handle.await?;
    assert_eq!(repo.pending().await?, 0);
    assert_chain_valid(&repo, 50).await?;

    db.drop_db().await
}

// ---------------------------------------------------------------------------
// Repositories on a real database + atomic "state change + audit" unit of work
// ---------------------------------------------------------------------------

use korgan::adapters::outbound::postgres::{
    PostgresSessionRepository, PostgresUnitOfWork, PostgresUserRepository,
};
use korgan::application::error::AppError;
use korgan::application::workers::EventBus;
use korgan::domain::entities::{Session, User};
use korgan::domain::value_objects::{EmailAddress, PasswordHash, UserId, Username};
use korgan::ports::errors::PortError;
use korgan::ports::repositories::{SessionRepository, UserRepository};

const DUMMY_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg";

fn new_user(n: u32) -> Result<User, Box<dyn std::error::Error>> {
    Ok(User::new(
        EmailAddress::parse(format!("real{n}@example.com"))?,
        Some(Username::new(format!("real{n}"))?),
        PasswordHash::new(DUMMY_HASH)?,
    ))
}

#[tokio::test]
#[ignore = "needs KORGAN_TEST_DATABASE_URL"]
async fn user_and_session_repositories_work_on_a_real_database() -> TestResult {
    let db = TestDb::create().await?;
    korgan::bootstrap::run_migrations(&db.pool).await?;
    let users = PostgresUserRepository::new(db.pool.clone());
    let sessions = PostgresSessionRepository::new(db.pool.clone());

    let mut user = new_user(1)?;
    users.create(&user).await?;
    let found = users
        .find_by_email(&user.email)
        .await?
        .ok_or("user missing")?;
    assert_eq!(found.id, user.id);

    user.status = korgan::domain::entities::AccountStatus::Active;
    users.update(&user).await?;
    assert!(users.find_by_id(&user.id).await?.is_some());

    // Uses the repository's own transaction (savepoint-capable path).
    users
        .update_password(&user.id, &PasswordHash::new(DUMMY_HASH)?, 5)
        .await?;

    let session = Session::new(
        user.id,
        "hash".to_owned(),
        std::net::IpAddr::from([127, 0, 0, 1]),
        None,
        None,
        chrono::Duration::hours(1),
    );
    sessions.create(&session).await?;
    assert!(sessions.find_by_id(&session.id).await?.is_some());

    db.drop_db().await
}

/// Builds a bus whose audit entries commit together with the work it wraps.
async fn atomic_bus(
    db: &TestDb,
) -> Result<(EventBus, std::sync::Arc<PostgresAuditLogRepository>), Box<dyn std::error::Error>> {
    korgan::bootstrap::run_migrations(&db.pool).await?;
    let audit = std::sync::Arc::new(PostgresAuditLogRepository::new(db.pool.clone()));
    let (bus, _rx) = EventBus::new(8);
    let bus = bus
        .with_audit_outbox(audit.clone())
        .with_unit_of_work(std::sync::Arc::new(PostgresUnitOfWork::new(
            db.pool.clone(),
        )));
    Ok((bus, audit))
}

async fn user_exists(users: &PostgresUserRepository, user: &User) -> Result<bool, PortError> {
    Ok(users.find_by_id(&user.id).await?.is_some())
}

#[tokio::test]
#[ignore = "needs KORGAN_TEST_DATABASE_URL"]
async fn audited_commits_the_state_change_and_its_audit_entry_together() -> TestResult {
    let db = TestDb::create().await?;
    let (bus, audit) = atomic_bus(&db).await?;
    let users = PostgresUserRepository::new(db.pool.clone());
    let user = new_user(1)?;

    let id: UserId = bus
        .audited(
            async {
                users.create(&user).await?;
                Ok::<_, AppError>(user.id)
            },
            entry(1),
        )
        .await?;

    assert_eq!(id, user.id);
    assert!(user_exists(&users, &user).await?);
    assert_eq!(audit.pending().await?, 1);
    db.drop_db().await
}

#[tokio::test]
#[ignore = "needs KORGAN_TEST_DATABASE_URL"]
async fn audited_rolls_everything_back_when_the_work_fails() -> TestResult {
    let db = TestDb::create().await?;
    let (bus, audit) = atomic_bus(&db).await?;
    let users = PostgresUserRepository::new(db.pool.clone());
    let user = new_user(1)?;

    let result: Result<(), AppError> = bus
        .audited(
            async {
                users.create(&user).await?;
                Err(AppError::Conflict) // fails after the write
            },
            entry(1),
        )
        .await;

    assert!(matches!(result, Err(AppError::Conflict)));
    assert!(
        !user_exists(&users, &user).await?,
        "state change must be rolled back"
    );
    assert_eq!(
        audit.pending().await?,
        0,
        "no audit entry for a failed change"
    );
    db.drop_db().await
}

/// Outbox whose enqueue always fails: the state change must not survive.
struct BrokenOutbox;

#[async_trait::async_trait]
impl korgan::ports::repositories::AuditOutbox for BrokenOutbox {
    async fn enqueue(&self, _entry: &AuditLog) -> Result<(), PortError> {
        Err(PortError::database("outbox down"))
    }
    async fn drain(&self, _limit: u32) -> Result<u32, PortError> {
        Ok(0)
    }
    async fn pending(&self) -> Result<u64, PortError> {
        Ok(0)
    }
}

#[tokio::test]
#[ignore = "needs KORGAN_TEST_DATABASE_URL"]
async fn audited_is_fail_closed_when_the_audit_entry_cannot_be_written() -> TestResult {
    let db = TestDb::create().await?;
    korgan::bootstrap::run_migrations(&db.pool).await?;
    let (bus, _rx) = EventBus::new(8);
    let bus = bus
        .with_audit_outbox(std::sync::Arc::new(BrokenOutbox))
        .with_unit_of_work(std::sync::Arc::new(PostgresUnitOfWork::new(
            db.pool.clone(),
        )));
    let users = PostgresUserRepository::new(db.pool.clone());
    let user = new_user(1)?;

    let result = bus
        .audited(
            async {
                users.create(&user).await?;
                Ok::<_, AppError>(())
            },
            entry(1),
        )
        .await;

    assert!(result.is_err());
    assert!(
        !user_exists(&users, &user).await?,
        "no audit => no state change"
    );
    db.drop_db().await
}

#[tokio::test]
#[ignore = "needs KORGAN_TEST_DATABASE_URL"]
async fn audited_rolls_back_when_the_caller_is_cancelled() -> TestResult {
    let db = TestDb::create().await?;
    let (bus, audit) = atomic_bus(&db).await?;
    let users = PostgresUserRepository::new(db.pool.clone());
    let user = new_user(1)?;

    // Client disconnect / timeout while the transaction is open.
    let outcome = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        bus.audited(
            async {
                users.create(&user).await?;
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                Ok::<_, AppError>(())
            },
            entry(1),
        ),
    )
    .await;

    assert!(outcome.is_err(), "the call must have been cancelled");
    assert!(!user_exists(&users, &user).await?);
    assert_eq!(audit.pending().await?, 0);
    db.drop_db().await
}

#[tokio::test]
#[ignore = "needs KORGAN_TEST_DATABASE_URL"]
async fn audited_reuses_one_connection_and_scales_under_concurrency() -> TestResult {
    let db = TestDb::create().await?;
    korgan::bootstrap::run_migrations(&db.pool).await?;

    // A pool of ONE connection: if repository calls inside the unit of work
    // used a second pooled connection they would deadlock.
    let tiny = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(db.pool.connect_options().as_ref().clone())
        .await?;
    let audit = std::sync::Arc::new(PostgresAuditLogRepository::new(tiny.clone()));
    let (bus, _rx) = EventBus::new(8);
    let bus = bus
        .with_audit_outbox(audit.clone())
        .with_unit_of_work(std::sync::Arc::new(PostgresUnitOfWork::new(tiny.clone())));
    let users = std::sync::Arc::new(PostgresUserRepository::new(tiny.clone()));

    let tasks: Vec<_> = (0..20u32)
        .map(|n| {
            let bus = bus.clone();
            let users = users.clone();
            tokio::spawn(async move {
                let user = new_user(n).map_err(|e| {
                    AppError::internal("user", std::io::Error::other(e.to_string()))
                })?;
                bus.audited(
                    async {
                        users.create(&user).await?;
                        Ok::<_, AppError>(())
                    },
                    entry(n),
                )
                .await
            })
        })
        .collect();
    for task in tasks {
        task.await??;
    }

    assert_eq!(audit.pending().await?, 20);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&db.pool)
        .await?;
    assert_eq!(count, 20);
    tiny.close().await;
    db.drop_db().await
}

// ---------------------------------------------------------------------------
// Benchmark (not a pass/fail test): cost of the audit paths on a real database.
//
//   KORGAN_TEST_DATABASE_URL=... cargo test --release --test real_db \
//       bench_audit_paths -- --ignored --nocapture
// ---------------------------------------------------------------------------

fn percentile(sorted: &[std::time::Duration], p: f64) -> f64 {
    let idx = ((sorted.len() as f64 * p) as usize).min(sorted.len().saturating_sub(1));
    sorted.get(idx).map_or(0.0, |d| d.as_secs_f64() * 1000.0)
}

#[allow(clippy::print_stderr)]
fn report(label: &str, mut samples: Vec<std::time::Duration>, wall: std::time::Duration) {
    samples.sort();
    eprintln!(
        "{label:<46} n={:<5} ops/s={:<8.0} p50={:.2}ms p95={:.2}ms p99={:.2}ms",
        samples.len(),
        samples.len() as f64 / wall.as_secs_f64(),
        percentile(&samples, 0.50),
        percentile(&samples, 0.95),
        percentile(&samples, 0.99),
    );
}

/// Runs `op` `total` times with `concurrency` parallel workers.
async fn measure<F, Fut>(
    total: u32,
    concurrency: u32,
    op: F,
) -> (Vec<std::time::Duration>, std::time::Duration)
where
    F: Fn(u32) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let started = std::time::Instant::now();
    let per_worker = total / concurrency;
    let workers: Vec<_> = (0..concurrency)
        .map(|w| {
            let op = op.clone();
            tokio::spawn(async move {
                let mut samples = Vec::with_capacity(per_worker as usize);
                for i in 0..per_worker {
                    let t0 = std::time::Instant::now();
                    op(w * per_worker + i).await;
                    samples.push(t0.elapsed());
                }
                samples
            })
        })
        .collect();
    let mut all = Vec::new();
    for w in workers {
        if let Ok(samples) = w.await {
            all.extend(samples);
        }
    }
    (all, started.elapsed())
}

#[tokio::test]
#[ignore = "benchmark; needs KORGAN_TEST_DATABASE_URL"]
#[allow(clippy::print_stderr)]
async fn bench_audit_paths() -> TestResult {
    let db = TestDb::create().await?;
    korgan::bootstrap::run_migrations(&db.pool).await?;
    let audit = std::sync::Arc::new(PostgresAuditLogRepository::new(db.pool.clone()));
    let users = std::sync::Arc::new(PostgresUserRepository::new(db.pool.clone()));
    let (bus, _rx) = EventBus::new(8);
    let bus = bus
        .with_audit_outbox(audit.clone())
        .with_unit_of_work(std::sync::Arc::new(PostgresUnitOfWork::new(
            db.pool.clone(),
        )));

    for concurrency in [1u32, 16] {
        eprintln!("--- concurrency {concurrency} ---");

        // Old path: one transaction + global advisory lock + chaining per event.
        let a = audit.clone();
        let (s, w) = measure(1600, concurrency, move |n| {
            let a = a.clone();
            async move {
                let mut e = entry(n);
                let _ = a.append_and_chain(&mut e).await;
            }
        })
        .await;
        report("legacy append_and_chain (lock+chain per event)", s, w);

        // New path: lock-free INSERT into the outbox.
        let a = audit.clone();
        let (s, w) = measure(1600, concurrency, move |n| {
            let a = a.clone();
            async move {
                let _ = a.enqueue(&entry(n)).await;
            }
        })
        .await;
        report("outbox enqueue (what the request pays)", s, w);

        // State change alone vs state change + atomic audit.
        let u = users.clone();
        let base = 1_000_000 * concurrency;
        let (s, w) = measure(800, concurrency, move |n| {
            let u = u.clone();
            async move {
                let user = match new_user(base + n) {
                    Ok(user) => user,
                    Err(_) => return,
                };
                let _ = u.create(&user).await;
            }
        })
        .await;
        report("create user only (no audit)", s, w);

        let (u, b) = (users.clone(), bus.clone());
        let base = 2_000_000 * concurrency;
        let (s, w) = measure(800, concurrency, move |n| {
            let (u, b) = (u.clone(), b.clone());
            async move {
                let user = match new_user(base + n) {
                    Ok(user) => user,
                    Err(_) => return,
                };
                let _ = b
                    .audited(
                        async {
                            u.create(&user).await?;
                            Ok::<(), AppError>(())
                        },
                        entry(n),
                    )
                    .await;
            }
        })
        .await;
        report("create user + atomic audit (audited)", s, w);
    }

    // Background chaining throughput of the worker side.
    let pending = audit.pending().await?;
    let t0 = std::time::Instant::now();
    while audit.pending().await? > 0 {
        audit.drain(200).await?;
    }
    let secs = t0.elapsed().as_secs_f64();
    eprintln!(
        "--- drain: {pending} queued entries chained in {secs:.2}s = {:.0} entries/s (batch 200, single drainer) ---",
        pending as f64 / secs
    );
    assert_chain_valid(&audit, usize::try_from(audit.count_all().await?)?).await?;

    db.drop_db().await
}
