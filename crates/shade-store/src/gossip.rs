//! Apply remote-origin upserts and deletes under last-write-wins.
//!
//! These are the entry points the mesh layer (`shade-mesh`, M4 PR B)
//! calls when it decodes an inbound `Upsert` or `Delete` frame. Every
//! function:
//!
//! 1. Compares `(updated_at, origin_node)` against the local row using
//!    SQL — same comparison the upsert paths bake into their `ON
//!    CONFLICT DO UPDATE` clauses.
//! 2. For mask upserts, additionally consults the `mask_tombstones`
//!    table — a tombstone newer than the inbound mask wins.
//! 3. Returns `bool`: `true` if the local store was modified, `false`
//!    if the inbound row lost the LWW comparison.
//!
//! These functions never touch `now_ms()`. The wire row's
//! `(updated_at, origin_node)` is authoritative — it was minted by the
//! origin node when the row first changed and must propagate verbatim,
//! otherwise LWW collapses.

use rusqlite::{params, OptionalExtension};
use shade_core::{
    Channel, ChannelId, ChannelSettings, ChannelUserFlags, FlagSet, Mask, MaskId, User, UserId,
};

use crate::{Store, StoreError};

// ----- user --------------------------------------------------------------

/// Apply a remote `User` upsert. Returns `true` if the local row was
/// inserted or updated, `false` if our copy was newer (LWW lost).
pub fn apply_user_upsert(store: &Store, user: &User) -> Result<bool, StoreError> {
    let mut conn = store.conn()?;
    let tx = conn.transaction()?;

    let n = tx.execute(
        "INSERT INTO users
            (id, handle, password_hash, is_bot, global_flags, comment,
             created_at, updated_at, origin_node)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(id) DO UPDATE SET
            handle        = excluded.handle,
            password_hash = excluded.password_hash,
            is_bot        = excluded.is_bot,
            global_flags  = excluded.global_flags,
            comment       = excluded.comment,
            updated_at    = excluded.updated_at,
            origin_node   = excluded.origin_node
         WHERE users.updated_at < excluded.updated_at
            OR (users.updated_at = excluded.updated_at
                AND users.origin_node > excluded.origin_node)",
        params![
            user.id.as_bytes().to_vec(),
            &user.handle,
            &user.password_hash,
            i64::from(user.is_bot),
            i64::from_le_bytes(user.global_flags.bits().to_le_bytes()),
            &user.comment,
            user.created_at,
            user.updated_at,
            &user.origin_node,
        ],
    )?;

    if n > 0 {
        // Replace the host list.
        tx.execute(
            "DELETE FROM user_hosts WHERE user_id = ?1",
            params![user.id.as_bytes().to_vec()],
        )?;
        for host in &user.hosts {
            tx.execute(
                "INSERT INTO user_hosts (user_id, hostmask) VALUES (?1, ?2)",
                params![user.id.as_bytes().to_vec(), host],
            )?;
        }
    }
    tx.commit()?;
    Ok(n > 0)
}

/// Apply a remote `User` delete under LWW.
pub fn apply_user_delete(
    store: &Store,
    id: UserId,
    updated_at: i64,
    origin_node: &str,
) -> Result<bool, StoreError> {
    let conn = store.conn()?;
    let n = conn.execute(
        "DELETE FROM users
         WHERE id = ?1
           AND (updated_at < ?2
                OR (updated_at = ?2 AND origin_node > ?3))",
        params![id.as_bytes().to_vec(), updated_at, origin_node],
    )?;
    Ok(n > 0)
}

// ----- channel -----------------------------------------------------------

pub fn apply_channel_upsert(store: &Store, channel: &Channel) -> Result<bool, StoreError> {
    let conn = store.conn()?;
    let n = conn.execute(
        "INSERT INTO channels (id, name, created_at, updated_at, origin_node)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET
            name        = excluded.name,
            updated_at  = excluded.updated_at,
            origin_node = excluded.origin_node
         WHERE channels.updated_at < excluded.updated_at
            OR (channels.updated_at = excluded.updated_at
                AND channels.origin_node > excluded.origin_node)",
        params![
            channel.id.as_bytes().to_vec(),
            &channel.name,
            channel.created_at,
            channel.updated_at,
            &channel.origin_node,
        ],
    )?;
    Ok(n > 0)
}

pub fn apply_channel_delete(
    store: &Store,
    id: ChannelId,
    updated_at: i64,
    origin_node: &str,
) -> Result<bool, StoreError> {
    let conn = store.conn()?;
    let n = conn.execute(
        "DELETE FROM channels
         WHERE id = ?1
           AND (updated_at < ?2
                OR (updated_at = ?2 AND origin_node > ?3))",
        params![id.as_bytes().to_vec(), updated_at, origin_node],
    )?;
    Ok(n > 0)
}

// ----- channel_settings --------------------------------------------------

pub fn apply_channel_settings_upsert(
    store: &Store,
    settings: &ChannelSettings,
) -> Result<bool, StoreError> {
    let conn = store.conn()?;
    let n = conn.execute(
        "INSERT INTO channel_settings
            (channel_id, flags, mode_pls, mode_mns, limit_prot,
             key_prot, topic_saved, updated_at, origin_node)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(channel_id) DO UPDATE SET
            flags       = excluded.flags,
            mode_pls    = excluded.mode_pls,
            mode_mns    = excluded.mode_mns,
            limit_prot  = excluded.limit_prot,
            key_prot    = excluded.key_prot,
            topic_saved = excluded.topic_saved,
            updated_at  = excluded.updated_at,
            origin_node = excluded.origin_node
         WHERE channel_settings.updated_at < excluded.updated_at
            OR (channel_settings.updated_at = excluded.updated_at
                AND channel_settings.origin_node > excluded.origin_node)",
        params![
            settings.channel_id.as_bytes().to_vec(),
            i64::from_le_bytes(settings.flags.bits().to_le_bytes()),
            &settings.mode_pls,
            &settings.mode_mns,
            settings.limit_prot,
            &settings.key_prot,
            &settings.topic_saved,
            settings.updated_at,
            &settings.origin_node,
        ],
    )?;
    Ok(n > 0)
}

// ----- channel_user_flags ------------------------------------------------

pub fn apply_channel_user_flags_upsert(
    store: &Store,
    row: &ChannelUserFlags,
) -> Result<bool, StoreError> {
    let conn = store.conn()?;
    let n = conn.execute(
        "INSERT INTO channel_user_flags
            (channel_id, user_id, flags, updated_at, origin_node)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(channel_id, user_id) DO UPDATE SET
            flags       = excluded.flags,
            updated_at  = excluded.updated_at,
            origin_node = excluded.origin_node
         WHERE channel_user_flags.updated_at < excluded.updated_at
            OR (channel_user_flags.updated_at = excluded.updated_at
                AND channel_user_flags.origin_node > excluded.origin_node)",
        params![
            row.channel_id.as_bytes().to_vec(),
            row.user_id.as_bytes().to_vec(),
            i64::from_le_bytes(row.flags.bits().to_le_bytes()),
            row.updated_at,
            &row.origin_node,
        ],
    )?;
    Ok(n > 0)
}

pub fn apply_channel_user_flags_delete(
    store: &Store,
    channel_id: ChannelId,
    user_id: UserId,
    updated_at: i64,
    origin_node: &str,
) -> Result<bool, StoreError> {
    let conn = store.conn()?;
    let n = conn.execute(
        "DELETE FROM channel_user_flags
         WHERE channel_id = ?1 AND user_id = ?2
           AND (updated_at < ?3
                OR (updated_at = ?3 AND origin_node > ?4))",
        params![
            channel_id.as_bytes().to_vec(),
            user_id.as_bytes().to_vec(),
            updated_at,
            origin_node,
        ],
    )?;
    Ok(n > 0)
}

// ----- mask --------------------------------------------------------------

/// Apply a remote `Mask` upsert. A pre-existing tombstone with newer or
/// lex-equal-better `(deleted_at, origin_node)` blocks the upsert — that's
/// the "deletes survive reorderings" property mesh gossip needs.
pub fn apply_mask_upsert(store: &Store, mask: &Mask) -> Result<bool, StoreError> {
    let conn = store.conn()?;
    // Tombstone gate (single conn — don't double-checkout from the pool).
    let tombstone: Option<(i64, String)> = conn
        .query_row(
            "SELECT deleted_at, origin_node FROM mask_tombstones WHERE id = ?1",
            params![mask.id.as_bytes().to_vec()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((deleted_at, ts_origin)) = tombstone {
        if deleted_at > mask.updated_at
            || (deleted_at == mask.updated_at && ts_origin <= mask.origin_node)
        {
            return Ok(false);
        }
    }
    let n = conn.execute(
        "INSERT INTO masklists
            (id, kind, channel_id, mask, reason, set_by, set_at,
             expires_at, sticky, updated_at, origin_node)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(id) DO UPDATE SET
            kind        = excluded.kind,
            channel_id  = excluded.channel_id,
            mask        = excluded.mask,
            reason      = excluded.reason,
            set_by      = excluded.set_by,
            set_at      = excluded.set_at,
            expires_at  = excluded.expires_at,
            sticky      = excluded.sticky,
            updated_at  = excluded.updated_at,
            origin_node = excluded.origin_node
         WHERE masklists.updated_at < excluded.updated_at
            OR (masklists.updated_at = excluded.updated_at
                AND masklists.origin_node > excluded.origin_node)",
        params![
            mask.id.as_bytes().to_vec(),
            mask.kind.as_i64(),
            mask.channel_id.as_ref().map(|c| c.as_bytes().to_vec()),
            &mask.mask,
            &mask.reason,
            &mask.set_by,
            mask.set_at,
            mask.expires_at,
            i64::from(mask.sticky),
            mask.updated_at,
            &mask.origin_node,
        ],
    )?;
    Ok(n > 0)
}

/// Apply a remote `Mask` delete. Removes the row (LWW-gated) and
/// records/refreshes the tombstone so a stale upsert arriving later
/// loses cleanly.
pub fn apply_mask_delete(
    store: &Store,
    id: MaskId,
    updated_at: i64,
    origin_node: &str,
) -> Result<bool, StoreError> {
    let mut conn = store.conn()?;
    let tx = conn.transaction()?;
    let row_n = tx.execute(
        "DELETE FROM masklists
         WHERE id = ?1
           AND (updated_at < ?2
                OR (updated_at = ?2 AND origin_node > ?3))",
        params![id.as_bytes().to_vec(), updated_at, origin_node],
    )?;
    let ts_n = tx.execute(
        "INSERT INTO mask_tombstones (id, deleted_at, origin_node)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(id) DO UPDATE SET
            deleted_at  = excluded.deleted_at,
            origin_node = excluded.origin_node
         WHERE mask_tombstones.deleted_at < excluded.deleted_at
            OR (mask_tombstones.deleted_at = excluded.deleted_at
                AND mask_tombstones.origin_node > excluded.origin_node)",
        params![id.as_bytes().to_vec(), updated_at, origin_node],
    )?;
    tx.commit()?;
    Ok(row_n > 0 || ts_n > 0)
}

// suppress dead-code warning for cross-crate consumption (FlagSet
// rebuilds aren't used in this module yet but bind the dependency).
#[allow(dead_code)]
fn _unused_flagset_dep(_: FlagSet) {}

#[cfg(test)]
mod tests {
    use super::*;
    use shade_core::{MaskKind, NewChannel, NewMask, NewUser};

    fn fresh_store() -> Store {
        let store = Store::open_in_memory().expect("open store");
        store.migrate().expect("migrate");
        store
    }

    fn alice(updated_at: i64, origin: &str) -> User {
        User {
            id: UserId::from_bytes([1; 16]),
            handle: "alice".into(),
            password_hash: None,
            is_bot: false,
            global_flags: FlagSet::NONE,
            comment: None,
            hosts: vec!["alice!*@*".into()],
            created_at: 0,
            updated_at,
            last_seen_at: None,
            origin_node: origin.into(),
        }
    }

    #[test]
    fn user_upsert_newer_remote_wins() {
        let store = fresh_store();
        assert!(apply_user_upsert(&store, &alice(100, "node-a")).unwrap());
        assert!(apply_user_upsert(&store, &alice(200, "node-b")).unwrap());
        let stored = crate::users::get_by_id(&store, UserId::from_bytes([1; 16]))
            .unwrap()
            .unwrap();
        assert_eq!(stored.updated_at, 200);
        assert_eq!(stored.origin_node, "node-b");
    }

    #[test]
    fn user_upsert_older_remote_loses() {
        let store = fresh_store();
        assert!(apply_user_upsert(&store, &alice(200, "node-b")).unwrap());
        assert!(!apply_user_upsert(&store, &alice(100, "node-a")).unwrap());
    }

    #[test]
    fn user_upsert_tie_broken_by_lex_smaller_origin() {
        let store = fresh_store();
        assert!(apply_user_upsert(&store, &alice(100, "node-b")).unwrap());
        // Same updated_at, lex-smaller origin → should win.
        assert!(apply_user_upsert(&store, &alice(100, "node-a")).unwrap());
        let stored = crate::users::get_by_id(&store, UserId::from_bytes([1; 16]))
            .unwrap()
            .unwrap();
        assert_eq!(stored.origin_node, "node-a");
    }

    #[test]
    fn user_delete_lww_gated() {
        let store = fresh_store();
        assert!(apply_user_upsert(&store, &alice(200, "node-a")).unwrap());
        // Stale delete loses.
        assert!(!apply_user_delete(&store, UserId::from_bytes([1; 16]), 100, "node-b").unwrap());
        assert!(crate::users::get_by_id(&store, UserId::from_bytes([1; 16]))
            .unwrap()
            .is_some());
        // Newer delete wins.
        assert!(apply_user_delete(&store, UserId::from_bytes([1; 16]), 300, "node-b").unwrap());
        assert!(crate::users::get_by_id(&store, UserId::from_bytes([1; 16]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn local_upsert_after_remote_keeps_newer_wins_property() {
        // Two local upserts at slightly different times — second should win.
        let store = fresh_store();
        let mut nu = NewUser {
            handle: "alice".into(),
            password_hash: None,
            is_bot: false,
            global_flags: FlagSet::NONE,
            comment: None,
            hosts: vec![],
        };
        crate::users::upsert(&store, &nu, "node-a").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        nu.comment = Some("updated".into());
        let after = crate::users::upsert(&store, &nu, "node-a").unwrap();
        assert_eq!(after.comment.as_deref(), Some("updated"));
    }

    #[test]
    fn mask_upsert_loses_to_existing_tombstone() {
        let store = fresh_store();
        let chan =
            crate::channels::upsert(&store, &NewChannel { name: "#x".into() }, "node-a").unwrap();
        // Local insert + delete leaves a tombstone.
        let mask = crate::masks::insert(
            &store,
            &NewMask {
                kind: MaskKind::Ban,
                channel_id: Some(chan.id),
                mask: "*!*@x".into(),
                reason: None,
                set_by: None,
                expires_at: None,
                sticky: false,
            },
            "node-a",
        )
        .unwrap();
        let mask_id = mask.id;
        assert!(crate::masks::delete(&store, mask_id, "node-a").unwrap());

        // An incoming remote mask upsert with an older updated_at must
        // lose to the tombstone.
        let mut stale = mask.clone();
        stale.updated_at = mask.updated_at - 1;
        stale.origin_node = "node-b".into();
        assert!(!apply_mask_upsert(&store, &stale).unwrap());
        assert!(crate::masks::get_by_id(&store, mask_id).unwrap().is_none());

        // A newer remote mask upsert defeats the tombstone.
        let mut fresh = mask.clone();
        fresh.updated_at = i64::MAX;
        fresh.origin_node = "node-b".into();
        assert!(apply_mask_upsert(&store, &fresh).unwrap());
        assert!(crate::masks::get_by_id(&store, mask_id).unwrap().is_some());
    }

    #[test]
    fn channel_settings_lww_round_trip() {
        let store = fresh_store();
        let chan =
            crate::channels::upsert(&store, &NewChannel { name: "#x".into() }, "node-a").unwrap();
        let s = ChannelSettings {
            channel_id: chan.id,
            flags: "+ax".parse().unwrap(),
            mode_pls: "ntC".into(),
            mode_mns: String::new(),
            limit_prot: None,
            key_prot: None,
            topic_saved: None,
            updated_at: 200,
            origin_node: "node-b".into(),
        };
        assert!(apply_channel_settings_upsert(&store, &s).unwrap());
        let mut stale = s.clone();
        stale.updated_at = 100;
        stale.flags = FlagSet::NONE;
        assert!(!apply_channel_settings_upsert(&store, &stale).unwrap());
        let read = crate::channels::get_settings(&store, chan.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            read.flags.to_string(),
            "+ax",
            "newer remote should be intact"
        );
    }
}
