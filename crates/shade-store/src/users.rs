//! User accessors.
//!
//! All upserts stamp `updated_at` and `origin_node`. Single-node M3 doesn't
//! enforce the last-write-wins gate at the SQL layer; M4 will add the
//! `WHERE excluded.updated_at >= updated_at` clause when mesh gossip starts
//! delivering peer-origin upserts.
//!
//! Hostmasks (`user_hosts`) are managed alongside the user row: replacing a
//! user's host list is a delete-all + insert-all in the same transaction.

use rusqlite::{params, OptionalExtension, Transaction};
use shade_core::{now_ms, FlagSet, NewUser, User, UserId};

use crate::{Store, StoreError};

/// Insert or update a user. Returns the row as it now exists in the
/// database (with the post-write `updated_at`).
pub fn upsert(store: &Store, new_user: &NewUser, origin_node: &str) -> Result<User, StoreError> {
    let mut conn = store.conn()?;
    let tx = conn.transaction()?;
    let user = upsert_in_tx(&tx, new_user, origin_node)?;
    tx.commit()?;
    Ok(user)
}

/// Insert/update a user inside an existing transaction. Lets callers
/// bundle a user write with related rows (hosts, channel flags) atomically.
pub fn upsert_in_tx(
    tx: &Transaction<'_>,
    new_user: &NewUser,
    origin_node: &str,
) -> Result<User, StoreError> {
    let now = now_ms();

    // Find an existing row by handle (case-insensitive — column is COLLATE NOCASE).
    let existing_id: Option<[u8; 16]> = tx
        .query_row(
            "SELECT id FROM users WHERE handle = ?1",
            params![&new_user.handle],
            |row| {
                row.get::<_, Vec<u8>>(0).map(|v| {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&v[..16]);
                    a
                })
            },
        )
        .optional()?;

    let (id, created_at) = match existing_id {
        Some(bytes) => {
            let id = UserId::from_bytes(bytes);
            let created_at: i64 = tx.query_row(
                "SELECT created_at FROM users WHERE id = ?1",
                params![&id.as_bytes().to_vec()],
                |row| row.get(0),
            )?;
            (id, created_at)
        }
        None => (UserId::new(), now),
    };

    tx.execute(
        "INSERT INTO users
            (id, handle, password_hash, is_bot, global_flags, comment,
             created_at, updated_at, origin_node)
         VALUES
            (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(id) DO UPDATE SET
            handle        = excluded.handle,
            password_hash = excluded.password_hash,
            is_bot        = excluded.is_bot,
            global_flags  = excluded.global_flags,
            comment       = excluded.comment,
            updated_at    = excluded.updated_at,
            origin_node   = excluded.origin_node",
        params![
            id.as_bytes().to_vec(),
            &new_user.handle,
            &new_user.password_hash,
            i64::from(new_user.is_bot),
            i64::from_le_bytes(new_user.global_flags.bits().to_le_bytes()),
            &new_user.comment,
            created_at,
            now,
            origin_node,
        ],
    )?;

    // Replace host list.
    tx.execute(
        "DELETE FROM user_hosts WHERE user_id = ?1",
        params![id.as_bytes().to_vec()],
    )?;
    for host in &new_user.hosts {
        tx.execute(
            "INSERT INTO user_hosts (user_id, hostmask) VALUES (?1, ?2)",
            params![id.as_bytes().to_vec(), host],
        )?;
    }

    Ok(User {
        id,
        handle: new_user.handle.clone(),
        password_hash: new_user.password_hash.clone(),
        is_bot: new_user.is_bot,
        global_flags: new_user.global_flags,
        comment: new_user.comment.clone(),
        hosts: new_user.hosts.clone(),
        created_at,
        updated_at: now,
        last_seen_at: None,
        origin_node: origin_node.to_owned(),
    })
}

/// Look up a user by ULID.
pub fn get_by_id(store: &Store, id: UserId) -> Result<Option<User>, StoreError> {
    let conn = store.conn()?;
    fetch_one(&conn, "id = ?1", params![id.as_bytes().to_vec()])
}

/// Look up a user by handle (case-insensitive).
pub fn get_by_handle(store: &Store, handle: &str) -> Result<Option<User>, StoreError> {
    let conn = store.conn()?;
    fetch_one(&conn, "handle = ?1", params![handle])
}

/// List all users, ordered by handle.
pub fn list(store: &Store) -> Result<Vec<User>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT id, handle, password_hash, is_bot, global_flags, comment,
                created_at, updated_at, last_seen_at, origin_node
         FROM users
         ORDER BY handle COLLATE NOCASE",
    )?;
    let rows = stmt
        .query_map([], |row| Ok(map_user_row(row)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut users = Vec::with_capacity(rows.len());
    for mut user in rows {
        user.hosts = fetch_hosts(&conn, user.id)?;
        users.push(user);
    }
    Ok(users)
}

/// Delete a user (cascades to user_hosts and channel_user_flags via FK).
pub fn delete(store: &Store, id: UserId) -> Result<bool, StoreError> {
    let conn = store.conn()?;
    let n = conn.execute(
        "DELETE FROM users WHERE id = ?1",
        params![id.as_bytes().to_vec()],
    )?;
    Ok(n > 0)
}

/// Update `last_seen_at` to `now_ms()` without bumping `updated_at` —
/// presence-tracking writes shouldn't fire LWW gossip churn.
pub fn touch_last_seen(store: &Store, id: UserId) -> Result<(), StoreError> {
    let conn = store.conn()?;
    conn.execute(
        "UPDATE users SET last_seen_at = ?1 WHERE id = ?2",
        params![now_ms(), id.as_bytes().to_vec()],
    )?;
    Ok(())
}

/// Match a `nick!user@host` string against every user's stored hostmasks
/// and return the first matching user. Used for passive identification
/// during JOIN policy. Returns `None` if no user has a matching hostmask.
///
/// **Identification only** — does *not* grant any permission by itself
/// (per Architecture.md § Authentication, hostmask matching never grants
/// permission; the per-channel flag set decides what the user can do).
pub fn match_by_host(store: &Store, host: &str) -> Result<Option<User>, StoreError> {
    let conn = store.conn()?;
    let mut user_stmt = conn.prepare(
        "SELECT u.id, u.handle, u.password_hash, u.is_bot, u.global_flags, u.comment,
                u.created_at, u.updated_at, u.last_seen_at, u.origin_node, h.hostmask
         FROM users u
         JOIN user_hosts h ON h.user_id = u.id",
    )?;
    let mut rows = user_stmt.query([])?;
    while let Some(row) = rows.next()? {
        let mask: String = row.get(10)?;
        if crate::masks::irc_glob_match(&mask, host) {
            let id_bytes: Vec<u8> = row.get(0)?;
            let mut id_arr = [0u8; 16];
            id_arr.copy_from_slice(&id_bytes[..16]);
            let flags_i64: i64 = row.get(4)?;
            let user = User {
                id: UserId::from_bytes(id_arr),
                handle: row.get(1)?,
                password_hash: row.get(2)?,
                is_bot: row.get::<_, i64>(3)? != 0,
                global_flags: FlagSet::from_bits(u64::from_le_bytes(flags_i64.to_le_bytes())),
                comment: row.get(5)?,
                hosts: Vec::new(),
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
                last_seen_at: row.get(8)?,
                origin_node: row.get(9)?,
            };
            // Refill the host list now that we know which user we want.
            drop(rows);
            drop(user_stmt);
            let mut full = user;
            full.hosts = fetch_hosts(&conn, full.id)?;
            return Ok(Some(full));
        }
    }
    Ok(None)
}

fn fetch_one(
    conn: &rusqlite::Connection,
    where_clause: &str,
    params: impl rusqlite::Params,
) -> Result<Option<User>, StoreError> {
    let sql = format!(
        "SELECT id, handle, password_hash, is_bot, global_flags, comment,
                created_at, updated_at, last_seen_at, origin_node
         FROM users
         WHERE {where_clause}"
    );
    let row = conn
        .query_row(&sql, params, |row| Ok(map_user_row(row)))
        .optional()?;
    let Some(mut user) = row else {
        return Ok(None);
    };
    user.hosts = fetch_hosts(conn, user.id)?;
    Ok(Some(user))
}

fn fetch_hosts(conn: &rusqlite::Connection, id: UserId) -> Result<Vec<String>, StoreError> {
    let mut stmt =
        conn.prepare("SELECT hostmask FROM user_hosts WHERE user_id = ?1 ORDER BY hostmask")?;
    let hosts = stmt
        .query_map(params![id.as_bytes().to_vec()], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(hosts)
}

fn map_user_row(row: &rusqlite::Row<'_>) -> User {
    let id_bytes: Vec<u8> = row.get(0).unwrap();
    let mut id_arr = [0u8; 16];
    id_arr.copy_from_slice(&id_bytes[..16]);
    let flags_i64: i64 = row.get(4).unwrap();
    User {
        id: UserId::from_bytes(id_arr),
        handle: row.get(1).unwrap(),
        password_hash: row.get(2).unwrap(),
        is_bot: row.get::<_, i64>(3).unwrap() != 0,
        global_flags: FlagSet::from_bits(u64::from_le_bytes(flags_i64.to_le_bytes())),
        comment: row.get(5).unwrap(),
        hosts: Vec::new(), // filled by fetch_hosts
        created_at: row.get(6).unwrap(),
        updated_at: row.get(7).unwrap(),
        last_seen_at: row.get(8).unwrap(),
        origin_node: row.get(9).unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_store() -> Store {
        let store = Store::open_in_memory().expect("open store");
        store.migrate().expect("migrate");
        store
    }

    #[test]
    fn upsert_creates_user_and_get_by_handle_returns_it() {
        let store = fresh_store();
        let nu = NewUser {
            handle: "alice".into(),
            password_hash: None,
            is_bot: false,
            global_flags: "+a".parse().unwrap(),
            comment: Some("the boss".into()),
            hosts: vec!["*!*@trusted.example".into()],
        };
        let written = upsert(&store, &nu, "node-a").expect("upsert");
        assert_eq!(written.handle, "alice");
        assert_eq!(written.global_flags.to_string(), "+a");
        assert_eq!(written.hosts, vec!["*!*@trusted.example"]);
        assert_eq!(written.origin_node, "node-a");

        let fetched = get_by_handle(&store, "ALICE").expect("get").unwrap();
        assert_eq!(fetched.id, written.id);
        assert_eq!(fetched.hosts, vec!["*!*@trusted.example"]);
    }

    #[test]
    fn upsert_is_idempotent_on_handle() {
        let store = fresh_store();
        let nu = NewUser {
            handle: "alice".into(),
            password_hash: None,
            is_bot: false,
            global_flags: FlagSet::NONE,
            comment: None,
            hosts: vec![],
        };
        let first = upsert(&store, &nu, "node-a").expect("first");
        let second = upsert(
            &store,
            &NewUser {
                handle: "alice".into(),
                comment: Some("updated".into()),
                ..nu.clone()
            },
            "node-a",
        )
        .expect("second");
        assert_eq!(first.id, second.id, "same handle should keep same id");
        assert_eq!(second.comment.as_deref(), Some("updated"));
    }

    #[test]
    fn upsert_replaces_host_list_atomically() {
        let store = fresh_store();
        let nu = NewUser {
            handle: "alice".into(),
            password_hash: None,
            is_bot: false,
            global_flags: FlagSet::NONE,
            comment: None,
            hosts: vec!["*!*@old.example".into()],
        };
        let _ = upsert(&store, &nu, "node-a").expect("v1");
        let updated = upsert(
            &store,
            &NewUser {
                hosts: vec!["*!*@new.example".into(), "*!*@also.example".into()],
                ..nu
            },
            "node-a",
        )
        .expect("v2");
        let mut hosts = updated.hosts;
        hosts.sort();
        assert_eq!(hosts, vec!["*!*@also.example", "*!*@new.example"]);
    }

    #[test]
    fn list_returns_users_alphabetically() {
        let store = fresh_store();
        for handle in ["charlie", "alice", "bob"] {
            let nu = NewUser {
                handle: handle.into(),
                password_hash: None,
                is_bot: false,
                global_flags: FlagSet::NONE,
                comment: None,
                hosts: vec![],
            };
            upsert(&store, &nu, "node-a").unwrap();
        }
        let users = list(&store).unwrap();
        let handles: Vec<&str> = users.iter().map(|u| u.handle.as_str()).collect();
        assert_eq!(handles, vec!["alice", "bob", "charlie"]);
    }

    #[test]
    fn delete_removes_user_and_hosts() {
        let store = fresh_store();
        let nu = NewUser {
            handle: "alice".into(),
            password_hash: None,
            is_bot: false,
            global_flags: FlagSet::NONE,
            comment: None,
            hosts: vec!["*!*@h.example".into()],
        };
        let user = upsert(&store, &nu, "node-a").unwrap();
        assert!(delete(&store, user.id).unwrap());
        assert!(get_by_id(&store, user.id).unwrap().is_none());

        // user_hosts should cascade.
        let count: i64 = store
            .conn()
            .unwrap()
            .query_row("SELECT count(*) FROM user_hosts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn touch_last_seen_does_not_bump_updated_at() {
        let store = fresh_store();
        let nu = NewUser {
            handle: "alice".into(),
            password_hash: None,
            is_bot: false,
            global_flags: FlagSet::NONE,
            comment: None,
            hosts: vec![],
        };
        let user = upsert(&store, &nu, "node-a").unwrap();
        let before = user.updated_at;
        std::thread::sleep(std::time::Duration::from_millis(2));
        touch_last_seen(&store, user.id).unwrap();
        let after = get_by_id(&store, user.id).unwrap().unwrap();
        assert_eq!(after.updated_at, before, "updated_at must not change");
        assert!(after.last_seen_at.is_some(), "last_seen_at should be set");
    }

    #[test]
    fn match_by_host_returns_user_with_matching_hostmask() {
        let store = fresh_store();
        let alice = upsert(
            &store,
            &NewUser {
                handle: "alice".into(),
                password_hash: None,
                is_bot: false,
                global_flags: FlagSet::NONE,
                comment: None,
                hosts: vec!["*!*@trusted.example".into(), "alice!*@*".into()],
            },
            "node-a",
        )
        .unwrap();
        let _bob = upsert(
            &store,
            &NewUser {
                handle: "bob".into(),
                password_hash: None,
                is_bot: false,
                global_flags: FlagSet::NONE,
                comment: None,
                hosts: vec!["bob!*@*".into()],
            },
            "node-a",
        )
        .unwrap();

        let matched = match_by_host(&store, "alice!ident@trusted.example")
            .unwrap()
            .unwrap();
        assert_eq!(matched.id, alice.id);
        assert_eq!(matched.hosts.len(), 2, "host list rehydrates on match");

        // No user matches an entirely different host.
        assert!(match_by_host(&store, "stranger!u@other.example")
            .unwrap()
            .is_none());
    }

    #[test]
    fn flagset_round_trips_through_sqlite_integer_column() {
        let store = fresh_store();
        let flags: FlagSet = "+oxv".parse().unwrap();
        let nu = NewUser {
            handle: "alice".into(),
            password_hash: None,
            is_bot: false,
            global_flags: flags,
            comment: None,
            hosts: vec![],
        };
        let written = upsert(&store, &nu, "node-a").unwrap();
        assert_eq!(written.global_flags, flags);
        let reread = get_by_id(&store, written.id).unwrap().unwrap();
        assert_eq!(reread.global_flags, flags);
    }
}
