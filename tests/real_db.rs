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
