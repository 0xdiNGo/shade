//! `shade backup` and `shade restore` subcommands.
//!
//! `backup` uses the rusqlite online backup API to produce a consistent
//! snapshot without blocking writers, then verifies the output with
//! `PRAGMA integrity_check`.
//!
//! `restore` copies the backup file to the data directory atomically
//! (write to a `.tmp` side file, fsync, rename) and then runs `shade migrate`
//! to bring the schema up to date.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rusqlite::{backup::Backup, Connection, ErrorCode};

// ── helpers ──────────────────────────────────────────────────────────────────

/// UTC timestamp suffix for auto-named backup files (filesystem-safe ISO-8601).
fn utc_stamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, mo, d, h, mi, s) = epoch_to_ymd_hms(secs);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

fn epoch_to_ymd_hms(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = secs % 60;
    let mins = secs / 60;
    let mi = mins % 60;
    let hours = mins / 60;
    let h = hours % 24;
    let days = hours / 24;
    let (y, mo, d) = days_to_ymd(days);
    (y, mo, d, h, mi, s)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970_u64;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: &[u64] = if leap {
        &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1_u64;
    for &md in month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Resolve the final backup destination path.
///
/// - `None` → caller writes raw bytes to stdout.
/// - Directory → append `shade-<stamp>.db`.
/// - Anything else → use verbatim.
fn resolve_out(out: Option<&Path>) -> Option<PathBuf> {
    let out = out?;
    if out.is_dir() {
        Some(out.join(format!("shade-{}.db", utc_stamp())))
    } else {
        Some(out.to_path_buf())
    }
}

/// Run the online SQLite backup from `src_path` to `dst_path`.
fn sqlite_backup(src_path: &Path, dst_path: &Path) -> Result<()> {
    let src = Connection::open(src_path)
        .with_context(|| format!("opening source db {}", src_path.display()))?;
    let mut dst = Connection::open(dst_path)
        .with_context(|| format!("opening destination db {}", dst_path.display()))?;
    let backup = Backup::new(&src, &mut dst)
        .with_context(|| format!("initialising backup from {}", src_path.display()))?;
    backup
        .run_to_completion(5, Duration::from_millis(50), None)
        .context("backup run_to_completion failed")?;
    Ok(())
}

/// Open the backup file and run `PRAGMA integrity_check`. Returns `Ok(())` only
/// when SQLite reports `ok`.
fn verify_integrity(path: &Path) -> Result<()> {
    let conn = Connection::open(path)
        .with_context(|| format!("opening {} for integrity check", path.display()))?;
    let result: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .context("running PRAGMA integrity_check")?;
    if result.trim() != "ok" {
        bail!(
            "integrity_check reported problems in {}: {}",
            path.display(),
            result
        );
    }
    Ok(())
}

/// Returns `Ok(true)` if no other process holds an exclusive SQLite write lock
/// on `path`, `Ok(false)` if the database is busy (daemon is running), or
/// `Err` on unexpected errors.
///
/// Uses SQLite's own `BEGIN EXCLUSIVE` — safe, no `unsafe` block required.
/// Works on all platforms where rusqlite does.
fn db_not_locked(path: &Path) -> Result<bool> {
    let conn = Connection::open(path)
        .with_context(|| format!("opening {} for lock probe", path.display()))?;
    match conn.execute_batch("BEGIN EXCLUSIVE; ROLLBACK;") {
        Ok(()) => Ok(true),
        Err(e) => {
            let code = e.sqlite_error_code();
            if matches!(
                code,
                Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
            ) {
                Ok(false)
            } else {
                Err(e).with_context(|| format!("lock probe on {}", path.display()))
            }
        }
    }
}

// ── backup ───────────────────────────────────────────────────────────────────

/// Implementation of `shade backup`.
///
/// - `db_path` — source database (`<data_dir>/shade.db`).
/// - `out` — if `Some`, write to that path (auto-name when it's a directory);
///   if `None`, write the raw bytes to stdout.
pub fn run_backup(db_path: &Path, out: Option<&Path>) -> Result<()> {
    let dest = resolve_out(out);

    match dest {
        None => {
            // Backup to a side-car temp file in the same directory, then
            // stream it to stdout so the caller can pipe or redirect the binary.
            let dir = db_path.parent().unwrap_or_else(|| Path::new("."));
            let tmp_path = dir.join(format!("shade-backup-stdout-{}.db.tmp", utc_stamp()));
            sqlite_backup(db_path, &tmp_path)?;
            // Best-effort cleanup on any error path below.
            let result = (|| -> Result<()> {
                verify_integrity(&tmp_path)?;
                let bytes = fs::metadata(&tmp_path).context("stat temp backup")?.len();
                let data = fs::read(&tmp_path).context("reading temp backup")?;
                io::stdout()
                    .write_all(&data)
                    .context("writing backup to stdout")?;
                eprintln!("ok: backed up {bytes} bytes to stdout");
                Ok(())
            })();
            let _ = fs::remove_file(&tmp_path);
            result?;
        }
        Some(dest_path) => {
            if let Some(parent) = dest_path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("creating {}", parent.display()))?;
                }
            }
            sqlite_backup(db_path, &dest_path)?;
            verify_integrity(&dest_path)?;
            let bytes = fs::metadata(&dest_path).context("stat backup")?.len();
            println!("ok: backed up {bytes} bytes to {}", dest_path.display());
        }
    }

    Ok(())
}

// ── restore ──────────────────────────────────────────────────────────────────

/// Implementation of `shade restore`.
///
/// - `from_path` — source backup file.
/// - `dest_db`   — destination path (`<data_dir>/shade.db`).
/// - `force`     — if `false`, refuse when `dest_db` already exists.
///
/// Returns the number of migrations applied.
pub fn run_restore(from_path: &Path, dest_db: &Path, force: bool) -> Result<usize> {
    // 1. Verify the source before touching anything.
    if !from_path.exists() {
        bail!("backup file not found: {}", from_path.display());
    }
    verify_integrity(from_path).context("verifying source backup before restore")?;

    // 2. Guard: refuse to overwrite unless --force.
    if dest_db.exists() && !force {
        bail!(
            "{} already exists; pass --force to overwrite it",
            dest_db.display()
        );
    }

    // 3. Guard: refuse if another process holds an exclusive lock on the dest.
    //    Uses SQLite's own BEGIN EXCLUSIVE — no unsafe code required.
    if dest_db.exists() && !db_not_locked(dest_db).context("checking destination lock")? {
        bail!(
            "{} is held by another process (is the daemon running?); \
             stop it before restoring",
            dest_db.display()
        );
    }

    // 4. Atomic copy: write to <dest>.tmp, fsync, rename.
    let tmp_path = {
        let mut p = dest_db.as_os_str().to_owned();
        p.push(".tmp");
        PathBuf::from(p)
    };
    {
        let data =
            fs::read(from_path).with_context(|| format!("reading {}", from_path.display()))?;
        let mut f =
            File::create(&tmp_path).with_context(|| format!("creating {}", tmp_path.display()))?;
        f.write_all(&data)
            .with_context(|| format!("writing {}", tmp_path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp_path.display()))?;
    }
    fs::rename(&tmp_path, dest_db)
        .with_context(|| format!("renaming {} → {}", tmp_path.display(), dest_db.display()))?;

    let bytes = fs::metadata(dest_db).context("stat restored db")?.len();

    // 5. Run migrations so the schema catches up if the backup predates this binary.
    let store = shade_store::Store::open(dest_db)
        .with_context(|| format!("opening restored db {}", dest_db.display()))?;
    let report = store
        .migrate()
        .with_context(|| format!("running migrations on {}", dest_db.display()))?;

    println!(
        "ok: restored {bytes} bytes from {}; applied {} migration(s)",
        from_path.display(),
        report.applied
    );

    Ok(report.applied)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use shade_core::{FlagSet, NewUser};
    use shade_store::users;

    fn fresh_store_at(path: &Path) -> shade_store::Store {
        let store = shade_store::Store::open(path).expect("open store");
        store.migrate().expect("migrate");
        store
    }

    // 1. Round-trip: backup then restore, data survives.
    #[test]
    fn backup_restore_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("shade.db");
        let backup_path = dir.path().join("shade-backup.db");
        let restored_path = dir.path().join("shade-restored.db");

        // Populate the source DB.
        {
            let store = fresh_store_at(&db_path);
            users::upsert(
                &store,
                &NewUser {
                    handle: "alice".into(),
                    password_hash: None,
                    is_bot: false,
                    global_flags: FlagSet::NONE,
                    comment: Some("round-trip test".into()),
                    hosts: vec!["*!*@example.com".into()],
                },
                "node-a",
            )
            .expect("upsert");
        }

        // Backup.
        run_backup(&db_path, Some(&backup_path)).expect("backup");
        assert!(backup_path.exists(), "backup file should exist");

        // Restore to a different destination.
        run_restore(&backup_path, &restored_path, false).expect("restore");

        // Verify the user round-tripped.
        let store = shade_store::Store::open(&restored_path).expect("open restored");
        let user = users::get_by_handle(&store, "alice")
            .expect("query")
            .expect("user should exist");
        assert_eq!(user.handle, "alice");
        assert_eq!(user.comment.as_deref(), Some("round-trip test"));
        assert_eq!(user.hosts, vec!["*!*@example.com"]);
    }

    // 2. Corrupt a backup file → integrity_check must detect it.
    #[test]
    fn integrity_check_catches_corrupt_backup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("shade.db");
        let corrupt_path = dir.path().join("corrupt.db");

        fresh_store_at(&db_path);
        // Write garbage — not a valid SQLite file.
        fs::write(&corrupt_path, b"this is not a sqlite database -- corrupt")
            .expect("write corrupt");

        let err = verify_integrity(&corrupt_path).expect_err("should fail on corrupt file");
        let msg = err.to_string();
        assert!(
            msg.contains("integrity_check") || msg.contains("not a database"),
            "error should mention integrity check or not-a-database; got: {msg}"
        );
    }

    // 3. Restore refuses without --force when destination exists.
    #[test]
    fn restore_refuses_without_force_when_dest_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("shade.db");
        let backup_path = dir.path().join("shade-backup.db");

        fresh_store_at(&db_path);
        run_backup(&db_path, Some(&backup_path)).expect("backup");

        let err =
            run_restore(&backup_path, &db_path, false).expect_err("should refuse without --force");
        let msg = err.to_string();
        assert!(
            msg.contains("already exists") || msg.contains("--force"),
            "error should mention existing file and --force; got: {msg}"
        );
    }

    // 4. Restore with --force overwrites and runs migrations.
    #[test]
    fn restore_with_force_overwrites_and_migrates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("shade.db");
        let backup_path = dir.path().join("shade-backup.db");

        {
            let store = fresh_store_at(&db_path);
            users::upsert(
                &store,
                &NewUser {
                    handle: "alice".into(),
                    password_hash: None,
                    is_bot: false,
                    global_flags: FlagSet::NONE,
                    comment: None,
                    hosts: vec![],
                },
                "node-a",
            )
            .expect("upsert");
        }

        run_backup(&db_path, Some(&backup_path)).expect("backup");

        // Force-overwrite the same destination.
        let applied = run_restore(&backup_path, &db_path, true).expect("force restore");
        // A freshly-migrated backup → 0 pending migrations after restore.
        assert_eq!(
            applied, 0,
            "no pending migrations expected on a fresh backup"
        );

        // alice is still there.
        let store = shade_store::Store::open(&db_path).expect("open");
        let user = users::get_by_handle(&store, "alice")
            .expect("query")
            .expect("alice should survive force-restore");
        assert_eq!(user.handle, "alice");
    }

    // 5. Restore refuses while the database is locked by another connection.
    //    We simulate a "running daemon" by holding an open Connection with an
    //    active EXCLUSIVE transaction — SQLite's lock covers the file.
    #[test]
    fn restore_refuses_when_dest_locked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("shade.db");
        let backup_path = dir.path().join("shade-backup.db");

        fresh_store_at(&db_path);
        run_backup(&db_path, Some(&backup_path)).expect("backup");

        // Hold an exclusive SQLite lock in a separate Connection.
        let lock_conn = Connection::open(&db_path).expect("lock conn");
        lock_conn
            .execute_batch("BEGIN EXCLUSIVE;")
            .expect("begin exclusive");

        let err =
            run_restore(&backup_path, &db_path, true).expect_err("should refuse when db is locked");
        let msg = err.to_string();
        assert!(
            msg.contains("held by another process")
                || msg.contains("daemon")
                || msg.contains("busy")
                || msg.contains("locked"),
            "error should explain the lock situation; got: {msg}"
        );

        lock_conn.execute_batch("ROLLBACK;").ok();
    }

    // 6. Auto-name: passing a directory creates shade-<stamp>.db inside it.
    #[test]
    fn backup_to_directory_auto_names() {
        let src_dir = tempfile::tempdir().expect("tempdir src");
        let out_dir = tempfile::tempdir().expect("tempdir out");
        let db_path = src_dir.path().join("shade.db");

        fresh_store_at(&db_path);
        run_backup(&db_path, Some(out_dir.path())).expect("backup to dir");

        let entries: Vec<_> = fs::read_dir(out_dir.path())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "should have exactly one backup file");
        let name = entries[0].file_name().to_string_lossy().into_owned();
        assert!(
            name.starts_with("shade-")
                && std::path::Path::new(&name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("db")),
            "backup filename should match shade-<stamp>.db; got: {name}"
        );
    }
}
