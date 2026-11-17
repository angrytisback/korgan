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
