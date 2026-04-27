//! Channel accessors: channels, channel_settings, channel_user_flags.

use rusqlite::{params, OptionalExtension};
use shade_core::{
    now_ms, Channel, ChannelId, ChannelSettings, ChannelUserFlags, FlagSet, NewChannel, UserId,
};

use crate::{Store, StoreError};

// ----- channels -----------------------------------------------------------

/// Insert a channel by name (idempotent on name). Returns the row.
pub fn upsert(
    store: &Store,
    new_channel: &NewChannel,
    origin_node: &str,
) -> Result<Channel, StoreError> {
    let mut conn = store.conn()?;
    let tx = conn.transaction()?;
    let now = now_ms();

    let existing: Option<(Vec<u8>, i64)> = tx
        .query_row(
            "SELECT id, created_at FROM channels WHERE name = ?1",
            params![&new_channel.name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let (id, created_at) = match existing {
        Some((bytes, created_at)) => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&bytes[..16]);
            (ChannelId::from_bytes(a), created_at)
        }
        None => (ChannelId::new(), now),
    };

    // Local writes always win. Remote-origin upserts apply through
    // `crate::gossip::apply_channel_upsert`, which gates by LWW.
    tx.execute(
        "INSERT INTO channels (id, name, created_at, updated_at, origin_node)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET
            name        = excluded.name,
            updated_at  = excluded.updated_at,
            origin_node = excluded.origin_node",
        params![
            id.as_bytes().to_vec(),
            &new_channel.name,
            created_at,
            now,
            origin_node,
        ],
    )?;
    tx.commit()?;

    Ok(Channel {
        id,
        name: new_channel.name.clone(),
        created_at,
        updated_at: now,
        origin_node: origin_node.to_owned(),
    })
}

/// Look up a channel by id.
pub fn get_by_id(store: &Store, id: ChannelId) -> Result<Option<Channel>, StoreError> {
    let conn = store.conn()?;
    fetch_channel(&conn, "id = ?1", params![id.as_bytes().to_vec()])
}

/// Look up a channel by name (case-insensitive).
pub fn get_by_name(store: &Store, name: &str) -> Result<Option<Channel>, StoreError> {
    let conn = store.conn()?;
    fetch_channel(&conn, "name = ?1", params![name])
}

/// List channels with `updated_at > since_ts`, oldest-first. Used by
/// snapshot streaming.
pub fn list_since(store: &Store, since_ts: i64) -> Result<Vec<Channel>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT id, name, created_at, updated_at, origin_node
         FROM channels
         WHERE updated_at > ?1
         ORDER BY updated_at",
    )?;
    let rows = stmt
        .query_map(params![since_ts], |row| Ok(map_channel_row(row)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// List channel_settings rows with `updated_at > since_ts`, oldest-first.
pub fn list_settings_since(
    store: &Store,
    since_ts: i64,
) -> Result<Vec<ChannelSettings>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT channel_id, flags, mode_pls, mode_mns, limit_prot,
                key_prot, topic_saved, updated_at, origin_node
         FROM channel_settings
         WHERE updated_at > ?1
         ORDER BY updated_at",
    )?;
    let rows = stmt
        .query_map(params![since_ts], |row| Ok(map_settings_row(row)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// List channel_user_flags rows with `updated_at > since_ts`,
/// oldest-first.
pub fn list_user_flags_since(
    store: &Store,
    since_ts: i64,
) -> Result<Vec<ChannelUserFlags>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT channel_id, user_id, flags, updated_at, origin_node
         FROM channel_user_flags
         WHERE updated_at > ?1
         ORDER BY updated_at",
    )?;
    let rows = stmt
        .query_map(params![since_ts], |row| Ok(map_user_flags_row(row)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// List channels, ordered by name.
pub fn list(store: &Store) -> Result<Vec<Channel>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT id, name, created_at, updated_at, origin_node
         FROM channels
         ORDER BY name COLLATE NOCASE",
    )?;
    let rows = stmt
        .query_map([], |row| Ok(map_channel_row(row)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Delete a channel (cascades to channel_settings, channel_user_flags,
/// masklists via FK).
pub fn delete(store: &Store, id: ChannelId) -> Result<bool, StoreError> {
    let conn = store.conn()?;
    let n = conn.execute(
        "DELETE FROM channels WHERE id = ?1",
        params![id.as_bytes().to_vec()],
    )?;
    Ok(n > 0)
}

fn fetch_channel(
    conn: &rusqlite::Connection,
    where_clause: &str,
    params: impl rusqlite::Params,
) -> Result<Option<Channel>, StoreError> {
    let sql = format!(
        "SELECT id, name, created_at, updated_at, origin_node
         FROM channels
         WHERE {where_clause}"
    );
    let row = conn
        .query_row(&sql, params, |row| Ok(map_channel_row(row)))
        .optional()?;
    Ok(row)
}

fn map_channel_row(row: &rusqlite::Row<'_>) -> Channel {
    let id_bytes: Vec<u8> = row.get(0).unwrap();
    let mut a = [0u8; 16];
    a.copy_from_slice(&id_bytes[..16]);
    Channel {
        id: ChannelId::from_bytes(a),
        name: row.get(1).unwrap(),
        created_at: row.get(2).unwrap(),
        updated_at: row.get(3).unwrap(),
        origin_node: row.get(4).unwrap(),
    }
}

// ----- channel_settings ---------------------------------------------------

/// Upsert per-channel settings. Returns the row as written.
pub fn upsert_settings(
    store: &Store,
    settings: &ChannelSettings,
    origin_node: &str,
) -> Result<ChannelSettings, StoreError> {
    let conn = store.conn()?;
    let now = now_ms();
    conn.execute(
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
            origin_node = excluded.origin_node",
        params![
            settings.channel_id.as_bytes().to_vec(),
            i64::from_le_bytes(settings.flags.bits().to_le_bytes()),
            &settings.mode_pls,
            &settings.mode_mns,
            settings.limit_prot,
            &settings.key_prot,
            &settings.topic_saved,
            now,
            origin_node,
        ],
    )?;
    Ok(ChannelSettings {
        updated_at: now,
        origin_node: origin_node.to_owned(),
        ..settings.clone()
    })
}

/// Get settings for a channel.
pub fn get_settings(
    store: &Store,
    channel_id: ChannelId,
) -> Result<Option<ChannelSettings>, StoreError> {
    let conn = store.conn()?;
    let row = conn
        .query_row(
            "SELECT channel_id, flags, mode_pls, mode_mns, limit_prot,
                    key_prot, topic_saved, updated_at, origin_node
             FROM channel_settings
             WHERE channel_id = ?1",
            params![channel_id.as_bytes().to_vec()],
            |row| Ok(map_settings_row(row)),
        )
        .optional()?;
    Ok(row)
}

fn map_settings_row(row: &rusqlite::Row<'_>) -> ChannelSettings {
    let id_bytes: Vec<u8> = row.get(0).unwrap();
    let mut a = [0u8; 16];
    a.copy_from_slice(&id_bytes[..16]);
    let flags_i64: i64 = row.get(1).unwrap();
    ChannelSettings {
        channel_id: ChannelId::from_bytes(a),
        flags: FlagSet::from_bits(u64::from_le_bytes(flags_i64.to_le_bytes())),
        mode_pls: row.get(2).unwrap(),
        mode_mns: row.get(3).unwrap(),
        limit_prot: row.get(4).unwrap(),
        key_prot: row.get(5).unwrap(),
        topic_saved: row.get(6).unwrap(),
        updated_at: row.get(7).unwrap(),
        origin_node: row.get(8).unwrap(),
    }
}

// ----- channel_user_flags -------------------------------------------------

/// Upsert a `(channel, user)` flag row.
pub fn upsert_user_flags(
    store: &Store,
    channel_id: ChannelId,
    user_id: UserId,
    flags: FlagSet,
    origin_node: &str,
) -> Result<ChannelUserFlags, StoreError> {
    let conn = store.conn()?;
    let now = now_ms();
    conn.execute(
        "INSERT INTO channel_user_flags
            (channel_id, user_id, flags, updated_at, origin_node)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(channel_id, user_id) DO UPDATE SET
            flags       = excluded.flags,
            updated_at  = excluded.updated_at,
            origin_node = excluded.origin_node",
        params![
            channel_id.as_bytes().to_vec(),
            user_id.as_bytes().to_vec(),
            i64::from_le_bytes(flags.bits().to_le_bytes()),
            now,
            origin_node,
        ],
    )?;
    Ok(ChannelUserFlags {
        channel_id,
        user_id,
        flags,
        updated_at: now,
        origin_node: origin_node.to_owned(),
    })
}

/// Read the per-channel flags for one user. `None` if no row exists (treat
/// as empty flag set).
pub fn get_user_flags(
    store: &Store,
    channel_id: ChannelId,
    user_id: UserId,
) -> Result<Option<ChannelUserFlags>, StoreError> {
    let conn = store.conn()?;
    let row = conn
        .query_row(
            "SELECT channel_id, user_id, flags, updated_at, origin_node
             FROM channel_user_flags
             WHERE channel_id = ?1 AND user_id = ?2",
            params![channel_id.as_bytes().to_vec(), user_id.as_bytes().to_vec()],
            |row| Ok(map_user_flags_row(row)),
        )
        .optional()?;
    Ok(row)
}

/// List `(channel, user)` flag rows for a channel.
pub fn list_user_flags(
    store: &Store,
    channel_id: ChannelId,
) -> Result<Vec<ChannelUserFlags>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT channel_id, user_id, flags, updated_at, origin_node
         FROM channel_user_flags
         WHERE channel_id = ?1",
    )?;
    let rows = stmt
        .query_map(params![channel_id.as_bytes().to_vec()], |row| {
            Ok(map_user_flags_row(row))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Delete the per-channel flags for a user.
pub fn delete_user_flags(
    store: &Store,
    channel_id: ChannelId,
    user_id: UserId,
) -> Result<bool, StoreError> {
    let conn = store.conn()?;
    let n = conn.execute(
        "DELETE FROM channel_user_flags WHERE channel_id = ?1 AND user_id = ?2",
        params![channel_id.as_bytes().to_vec(), user_id.as_bytes().to_vec()],
    )?;
    Ok(n > 0)
}

fn map_user_flags_row(row: &rusqlite::Row<'_>) -> ChannelUserFlags {
    let chan_bytes: Vec<u8> = row.get(0).unwrap();
    let user_bytes: Vec<u8> = row.get(1).unwrap();
    let mut chan = [0u8; 16];
    let mut user = [0u8; 16];
    chan.copy_from_slice(&chan_bytes[..16]);
    user.copy_from_slice(&user_bytes[..16]);
    let flags_i64: i64 = row.get(2).unwrap();
    ChannelUserFlags {
        channel_id: ChannelId::from_bytes(chan),
        user_id: UserId::from_bytes(user),
        flags: FlagSet::from_bits(u64::from_le_bytes(flags_i64.to_le_bytes())),
        updated_at: row.get(3).unwrap(),
        origin_node: row.get(4).unwrap(),
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
    fn upsert_then_get_by_name() {
        let store = fresh_store();
        let chan = upsert(
            &store,
            &NewChannel {
                name: "#shade-test".into(),
            },
            "node-a",
        )
        .unwrap();
        let fetched = get_by_name(&store, "#SHADE-TEST").unwrap().unwrap();
        assert_eq!(fetched.id, chan.id);
        assert_eq!(fetched.name, "#shade-test");
    }

    #[test]
    fn upsert_is_idempotent_on_name() {
        let store = fresh_store();
        let a = upsert(&store, &NewChannel { name: "#x".into() }, "node-a").unwrap();
        let b = upsert(&store, &NewChannel { name: "#x".into() }, "node-a").unwrap();
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn settings_upsert_round_trips() {
        let store = fresh_store();
        let chan = upsert(&store, &NewChannel { name: "#x".into() }, "node-a").unwrap();
        let settings = ChannelSettings {
            channel_id: chan.id,
            flags: "+ax".parse().unwrap(),
            mode_pls: "ntC".into(),
            mode_mns: "s".into(),
            limit_prot: Some(50),
            key_prot: Some("hunter2".into()),
            topic_saved: Some("Hello".into()),
            updated_at: 0,
            origin_node: String::new(),
        };
        let written = upsert_settings(&store, &settings, "node-a").unwrap();
        assert!(written.updated_at > 0);
        let read = get_settings(&store, chan.id).unwrap().unwrap();
        assert_eq!(read.flags.to_string(), "+ax");
        assert_eq!(read.mode_pls, "ntC");
        assert_eq!(read.limit_prot, Some(50));
    }

    #[test]
    fn user_flags_upsert_and_list() {
        let store = fresh_store();
        let chan = upsert(&store, &NewChannel { name: "#x".into() }, "node-a").unwrap();

        // Need a user for the FK to satisfy.
        let nu = shade_core::NewUser {
            handle: "alice".into(),
            password_hash: None,
            is_bot: false,
            global_flags: FlagSet::NONE,
            comment: None,
            hosts: vec![],
        };
        let user = crate::users::upsert(&store, &nu, "node-a").unwrap();

        let flags: FlagSet = "+ov".parse().unwrap();
        let row = upsert_user_flags(&store, chan.id, user.id, flags, "node-a").unwrap();
        assert_eq!(row.flags, flags);

        let listed = list_user_flags(&store, chan.id).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].flags.to_string(), "+ov");

        // Update flags.
        let updated_flags: FlagSet = "+oxv".parse().unwrap();
        upsert_user_flags(&store, chan.id, user.id, updated_flags, "node-a").unwrap();
        let read = get_user_flags(&store, chan.id, user.id).unwrap().unwrap();
        assert_eq!(read.flags, updated_flags);
    }

    #[test]
    fn delete_channel_cascades_settings_and_flags() {
        let store = fresh_store();
        let chan = upsert(&store, &NewChannel { name: "#x".into() }, "node-a").unwrap();
        upsert_settings(
            &store,
            &ChannelSettings {
                channel_id: chan.id,
                flags: FlagSet::NONE,
                mode_pls: String::new(),
                mode_mns: String::new(),
                limit_prot: None,
                key_prot: None,
                topic_saved: None,
                updated_at: 0,
                origin_node: String::new(),
            },
            "node-a",
        )
        .unwrap();

        assert!(delete(&store, chan.id).unwrap());
        assert!(get_settings(&store, chan.id).unwrap().is_none());
    }
}
