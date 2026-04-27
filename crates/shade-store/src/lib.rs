//! Shade persistent store.
//!
//! SQLite-backed (bundled libsqlite3) connection pool with refinery-managed
//! migrations. Every replicated table carries `(updated_at, origin_node)` so
//! gossip can resolve conflicts via last-write-wins.

use std::path::{Path, PathBuf};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

pub mod audit;
pub mod auth_tokens;
pub mod channels;
pub mod gossip;
pub mod masks;
mod migrations;
pub mod users;

/// SQLite-backed Shade store.
pub struct Store {
    pool: Pool<SqliteConnectionManager>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("opening sqlite at {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: r2d2::Error,
    },
    #[error("checking out connection: {0}")]
    Pool(#[from] r2d2::Error),
    #[error("sqlite error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] refinery::Error),
}

/// Outcome of a migration run.
#[derive(Debug, Clone)]
pub struct MigrationReport {
    /// Number of migrations applied during this run.
    pub applied: usize,
}

impl Store {
    /// Open or create a Shade SQLite database at `path`. Does **not** run
    /// migrations — call [`Store::migrate`] afterwards. Splitting the two
    /// lets `shade migrate` report exactly what it applied.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let manager = SqliteConnectionManager::file(path).with_init(|conn| {
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = NORMAL;
                 PRAGMA foreign_keys = ON;",
            )
        });
        let pool = Pool::new(manager).map_err(|source| StoreError::Open {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self { pool })
    }

    /// Open a fresh in-memory database. Like [`Store::open`], does **not**
    /// run migrations. Each call returns an independent database; used in
    /// tests.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let manager = SqliteConnectionManager::memory()
            .with_init(|conn| conn.execute_batch("PRAGMA foreign_keys = ON;"));
        let pool = Pool::builder()
            .max_size(1)
            .build(manager)
            .map_err(|source| StoreError::Open {
                path: PathBuf::from(":memory:"),
                source,
            })?;
        Ok(Self { pool })
    }

    /// Run any pending migrations against this store.
    pub fn migrate(&self) -> Result<MigrationReport, StoreError> {
        let mut conn = self.pool.get()?;
        let report = migrations::runner().run(&mut *conn)?;
        Ok(MigrationReport {
            applied: report.applied_migrations().len(),
        })
    }

    /// Return a pooled connection for ad-hoc queries.
    pub fn conn(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>, StoreError> {
        Ok(self.pool.get()?)
    }

    /// Run a quick sanity probe (`SELECT 1`) to confirm the store is healthy.
    /// Used by `/readyz`.
    pub fn probe(&self) -> Result<(), StoreError> {
        let conn = self.conn()?;
        let one: i64 = conn.query_row("SELECT 1", [], |row| row.get(0))?;
        debug_assert_eq!(one, 1);
        Ok(())
    }
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

/// Re-export of `Connection` for callers that build statements directly.
pub use rusqlite::Connection as RusqliteConnection;

/// Resolve the on-disk database path from a node's `data_dir`.
#[must_use]
pub fn db_path_in(data_dir: &Path) -> PathBuf {
    data_dir.join("shade.db")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn assert_table_exists(conn: &Connection, name: &str) {
        let exists: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .expect("query");
        assert_eq!(exists, 1, "expected table `{name}` to exist");
    }

    #[test]
    fn migrate_applies_then_idempotent() {
        let store = Store::open_in_memory().expect("open store");
        let first = store.migrate().expect("first migrate");
        assert!(first.applied >= 1, "first migrate should apply migrations");
        let second = store.migrate().expect("second migrate");
        assert_eq!(second.applied, 0, "second migrate should be a no-op");
    }

    #[test]
    fn schema_has_all_mvp_tables() {
        let store = Store::open_in_memory().expect("open store");
        store.migrate().expect("migrate");
        let conn = store.conn().expect("checkout conn");
        for name in [
            "users",
            "user_hosts",
            "channels",
            "channel_settings",
            "channel_user_flags",
            "masklists",
            "peers",
            "role_assignments",
            "audit_log",
        ] {
            assert_table_exists(&conn, name);
        }
    }

    #[test]
    fn probe_succeeds_after_open() {
        let store = Store::open_in_memory().expect("open store");
        store.probe().expect("probe succeeds");
    }

    #[test]
    fn file_open_creates_db_and_persists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("shade.db");
        {
            let store = Store::open(&path).expect("open store");
            store.migrate().expect("migrate");
            store.probe().expect("probe");
            store
                .conn()
                .expect("checkout")
                .execute(
                    "INSERT INTO peers (node_id, cert_fpr, endpoint, added_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params!["shade-test-01", "abcd", "10.0.0.1:7331", 0_i64],
                )
                .expect("insert");
        }
        // Reopen, run migrate (no-op), confirm row persisted.
        let store = Store::open(&path).expect("reopen");
        let report = store.migrate().expect("migrate on reopen");
        assert_eq!(report.applied, 0, "no migrations to apply on reopen");
        let count: i64 = store
            .conn()
            .expect("checkout")
            .query_row("SELECT count(*) FROM peers", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 1);
    }
}
