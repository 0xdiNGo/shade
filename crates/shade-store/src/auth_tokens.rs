//! Bearer-token store for the admin API login flow.
//!
//! Tokens are local to one node — never gossipped — see the comment in
//! `migrations/V0003__auth_tokens.sql`.

use rusqlite::{params, OptionalExtension};
use shade_core::AuthTokenHash;

use crate::{Store, StoreError};

/// One row from `auth_tokens`. The wire-form token is **not** stored;
/// only the SHA-256 hash and metadata.
#[derive(Debug, Clone)]
pub struct StoredToken {
    pub hash: AuthTokenHash,
    pub handle: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub origin_node: String,
}

/// Insert a freshly-minted token. Returns the row as written.
pub fn insert(
    store: &Store,
    hash: &AuthTokenHash,
    handle: &str,
    expires_at: i64,
    created_at: i64,
    origin_node: &str,
) -> Result<StoredToken, StoreError> {
    let conn = store.conn()?;
    conn.execute(
        "INSERT INTO auth_tokens (hash, handle, expires_at, created_at, origin_node)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            hash.as_bytes().to_vec(),
            handle,
            expires_at,
            created_at,
            origin_node,
        ],
    )?;
    Ok(StoredToken {
        hash: *hash,
        handle: handle.to_owned(),
        expires_at,
        created_at,
        origin_node: origin_node.to_owned(),
    })
}

/// Look up a token by its hash. Does **not** consult `expires_at` —
/// callers are responsible for checking the expiry against `now_ms`.
/// (Splitting that out keeps the lookup hot path side-effect-free; the
/// daemon prunes expired rows via [`delete_expired`].)
pub fn get_by_hash(store: &Store, hash: &AuthTokenHash) -> Result<Option<StoredToken>, StoreError> {
    let conn = store.conn()?;
    let row = conn
        .query_row(
            "SELECT hash, handle, expires_at, created_at, origin_node
             FROM auth_tokens
             WHERE hash = ?1",
            params![hash.as_bytes().to_vec()],
            |row| {
                let h: Vec<u8> = row.get(0)?;
                let mut arr = [0u8; 32];
                if h.len() == 32 {
                    arr.copy_from_slice(&h);
                }
                Ok(StoredToken {
                    hash: AuthTokenHash(arr),
                    handle: row.get(1)?,
                    expires_at: row.get(2)?,
                    created_at: row.get(3)?,
                    origin_node: row.get(4)?,
                })
            },
        )
        .optional()?;
    Ok(row)
}

/// Delete a single token. Returns `true` when a row was removed.
pub fn delete(store: &Store, hash: &AuthTokenHash) -> Result<bool, StoreError> {
    let conn = store.conn()?;
    let n = conn.execute(
        "DELETE FROM auth_tokens WHERE hash = ?1",
        params![hash.as_bytes().to_vec()],
    )?;
    Ok(n > 0)
}

/// Delete every token whose `expires_at <= now_ms`. Returns the row
/// count for log lines.
pub fn delete_expired(store: &Store, now_ms: i64) -> Result<usize, StoreError> {
    let conn = store.conn()?;
    let n = conn.execute(
        "DELETE FROM auth_tokens WHERE expires_at <= ?1",
        params![now_ms],
    )?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shade_core::AuthToken;

    fn fresh_store() -> Store {
        let store = Store::open_in_memory().unwrap();
        store.migrate().unwrap();
        store
    }

    #[test]
    fn insert_then_lookup_round_trips() {
        let store = fresh_store();
        let tok = AuthToken::random();
        insert(&store, &tok.hash(), "alice", 1_000, 0, "node-a").unwrap();
        let row = get_by_hash(&store, &tok.hash()).unwrap().unwrap();
        assert_eq!(row.handle, "alice");
        assert_eq!(row.expires_at, 1_000);
        assert_eq!(row.origin_node, "node-a");
    }

    #[test]
    fn lookup_with_unknown_hash_returns_none() {
        let store = fresh_store();
        let other = AuthToken::random();
        assert!(get_by_hash(&store, &other.hash()).unwrap().is_none());
    }

    #[test]
    fn delete_removes_row() {
        let store = fresh_store();
        let tok = AuthToken::random();
        insert(&store, &tok.hash(), "alice", 1_000, 0, "node-a").unwrap();
        assert!(delete(&store, &tok.hash()).unwrap());
        assert!(get_by_hash(&store, &tok.hash()).unwrap().is_none());
        // Idempotent on a missing row.
        assert!(!delete(&store, &tok.hash()).unwrap());
    }

    #[test]
    fn delete_expired_drops_only_past_rows() {
        let store = fresh_store();
        let a = AuthToken::random();
        let b = AuthToken::random();
        insert(&store, &a.hash(), "alice", 100, 0, "n").unwrap();
        insert(&store, &b.hash(), "bob", 1_000, 0, "n").unwrap();
        let n = delete_expired(&store, 500).unwrap();
        assert_eq!(n, 1);
        assert!(get_by_hash(&store, &a.hash()).unwrap().is_none());
        assert!(get_by_hash(&store, &b.hash()).unwrap().is_some());
    }
}
