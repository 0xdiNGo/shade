//! Mask (ban/exempt/invite) accessors.

use rusqlite::{params, OptionalExtension};
use shade_core::{now_ms, ChannelId, Mask, MaskId, MaskKind, NewMask};

use crate::{Store, StoreError};

/// Insert a new mask. Returns the row as written.
pub fn insert(store: &Store, new_mask: &NewMask, origin_node: &str) -> Result<Mask, StoreError> {
    let conn = store.conn()?;
    let now = now_ms();
    let id = MaskId::new();
    conn.execute(
        "INSERT INTO masklists
            (id, kind, channel_id, mask, reason, set_by, set_at,
             expires_at, sticky, updated_at, origin_node)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            id.as_bytes().to_vec(),
            new_mask.kind.as_i64(),
            new_mask.channel_id.as_ref().map(|c| c.as_bytes().to_vec()),
            &new_mask.mask,
            &new_mask.reason,
            &new_mask.set_by,
            now,
            new_mask.expires_at,
            i64::from(new_mask.sticky),
            now,
            origin_node,
        ],
    )?;
    Ok(Mask {
        id,
        kind: new_mask.kind,
        channel_id: new_mask.channel_id,
        mask: new_mask.mask.clone(),
        reason: new_mask.reason.clone(),
        set_by: new_mask.set_by.clone(),
        set_at: now,
        expires_at: new_mask.expires_at,
        sticky: new_mask.sticky,
        updated_at: now,
        origin_node: origin_node.to_owned(),
    })
}

/// Look up a mask by id.
pub fn get_by_id(store: &Store, id: MaskId) -> Result<Option<Mask>, StoreError> {
    let conn = store.conn()?;
    let row = conn
        .query_row(
            "SELECT id, kind, channel_id, mask, reason, set_by, set_at,
                    expires_at, sticky, updated_at, origin_node
             FROM masklists
             WHERE id = ?1",
            params![id.as_bytes().to_vec()],
            |row| Ok(map_row(row)),
        )
        .optional()?;
    Ok(row)
}

/// List masks of a kind for a channel. `channel_id == None` returns the
/// network-wide global masks for that kind.
pub fn list(
    store: &Store,
    kind: MaskKind,
    channel_id: Option<ChannelId>,
) -> Result<Vec<Mask>, StoreError> {
    let conn = store.conn()?;
    let rows = if let Some(chan) = channel_id {
        let mut stmt = conn.prepare(
            "SELECT id, kind, channel_id, mask, reason, set_by, set_at,
                    expires_at, sticky, updated_at, origin_node
             FROM masklists
             WHERE kind = ?1 AND channel_id = ?2
             ORDER BY set_at",
        )?;
        let collected: Vec<Mask> = stmt
            .query_map(params![kind.as_i64(), chan.as_bytes().to_vec()], |row| {
                Ok(map_row(row))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        collected
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, kind, channel_id, mask, reason, set_by, set_at,
                    expires_at, sticky, updated_at, origin_node
             FROM masklists
             WHERE kind = ?1 AND channel_id IS NULL
             ORDER BY set_at",
        )?;
        let collected: Vec<Mask> = stmt
            .query_map(params![kind.as_i64()], |row| Ok(map_row(row)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        collected
    };
    Ok(rows)
}

/// Match a `nick!user@host` against the active ban list for `channel_id`
/// (plus network-wide bans). Returns the first matching ban, or `None`.
/// Exempt matches override bans: if `host` matches *any* exempt for the
/// same scope, no ban is returned.
pub fn match_ban(
    store: &Store,
    channel_id: ChannelId,
    host: &str,
) -> Result<Option<Mask>, StoreError> {
    // Pull both kinds in a single pass each.
    let bans = {
        let mut chan = list(store, MaskKind::Ban, Some(channel_id))?;
        chan.extend(list(store, MaskKind::Ban, None)?);
        chan
    };
    let exempts = {
        let mut chan = list(store, MaskKind::Exempt, Some(channel_id))?;
        chan.extend(list(store, MaskKind::Exempt, None)?);
        chan
    };
    if exempts.iter().any(|m| irc_glob_match(&m.mask, host)) {
        return Ok(None);
    }
    Ok(bans.into_iter().find(|m| irc_glob_match(&m.mask, host)))
}

/// Delete a mask by id.
pub fn delete(store: &Store, id: MaskId) -> Result<bool, StoreError> {
    let conn = store.conn()?;
    let n = conn.execute(
        "DELETE FROM masklists WHERE id = ?1",
        params![id.as_bytes().to_vec()],
    )?;
    Ok(n > 0)
}

fn map_row(row: &rusqlite::Row<'_>) -> Mask {
    let id_bytes: Vec<u8> = row.get(0).unwrap();
    let mut id_arr = [0u8; 16];
    id_arr.copy_from_slice(&id_bytes[..16]);
    let kind_i: i64 = row.get(1).unwrap();
    let chan_bytes: Option<Vec<u8>> = row.get(2).unwrap();
    let channel_id = chan_bytes.map(|b| {
        let mut a = [0u8; 16];
        a.copy_from_slice(&b[..16]);
        ChannelId::from_bytes(a)
    });
    Mask {
        id: MaskId::from_bytes(id_arr),
        kind: MaskKind::from_i64(kind_i).expect("masklists.kind always valid"),
        channel_id,
        mask: row.get(3).unwrap(),
        reason: row.get(4).unwrap(),
        set_by: row.get(5).unwrap(),
        set_at: row.get(6).unwrap(),
        expires_at: row.get(7).unwrap(),
        sticky: row.get::<_, i64>(8).unwrap() != 0,
        updated_at: row.get(9).unwrap(),
        origin_node: row.get(10).unwrap(),
    }
}

/// IRC-style glob match: `*` matches any (possibly empty) sequence; `?`
/// matches exactly one char. Case-insensitive ASCII compare. Pure
/// recursion + memoization-free since IRC masks rarely exceed a few
/// dozen characters; if performance ever matters, swap in a Glob impl.
#[must_use]
pub fn irc_glob_match(pattern: &str, target: &str) -> bool {
    fn lower(b: u8) -> u8 {
        if b.is_ascii_uppercase() {
            b + 32
        } else {
            b
        }
    }
    fn rec(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => rec(&p[1..], t) || (!t.is_empty() && rec(p, &t[1..])),
            (None, Some(_)) => false,
            (Some(_), None) => p.iter().all(|&c| c == b'*'),
            (Some(b'?'), Some(_)) => rec(&p[1..], &t[1..]),
            (Some(&pc), Some(&tc)) => lower(pc) == lower(tc) && rec(&p[1..], &t[1..]),
        }
    }
    rec(pattern.as_bytes(), target.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shade_core::NewChannel;

    fn fresh_store() -> Store {
        let store = Store::open_in_memory().expect("open store");
        store.migrate().expect("migrate");
        store
    }

    fn make_channel(store: &Store, name: &str) -> ChannelId {
        crate::channels::upsert(store, &NewChannel { name: name.into() }, "node-a")
            .unwrap()
            .id
    }

    #[test]
    fn insert_and_get_by_id() {
        let store = fresh_store();
        let chan = make_channel(&store, "#x");
        let nm = NewMask {
            kind: MaskKind::Ban,
            channel_id: Some(chan),
            mask: "*!*@evil.example".into(),
            reason: Some("flooding".into()),
            set_by: Some("alice".into()),
            expires_at: None,
            sticky: false,
        };
        let mask = insert(&store, &nm, "node-a").unwrap();
        let read = get_by_id(&store, mask.id).unwrap().unwrap();
        assert_eq!(read.mask, "*!*@evil.example");
        assert_eq!(read.kind, MaskKind::Ban);
        assert_eq!(read.channel_id, Some(chan));
    }

    #[test]
    fn list_returns_only_matching_kind_and_channel() {
        let store = fresh_store();
        let chan_a = make_channel(&store, "#a");
        let chan_b = make_channel(&store, "#b");
        for (kind, chan) in [
            (MaskKind::Ban, Some(chan_a)),
            (MaskKind::Ban, Some(chan_b)),
            (MaskKind::Exempt, Some(chan_a)),
            (MaskKind::Ban, None), // global
        ] {
            insert(
                &store,
                &NewMask {
                    kind,
                    channel_id: chan,
                    mask: "*!*@evil.example".into(),
                    reason: None,
                    set_by: None,
                    expires_at: None,
                    sticky: false,
                },
                "node-a",
            )
            .unwrap();
        }

        let bans_a = list(&store, MaskKind::Ban, Some(chan_a)).unwrap();
        assert_eq!(bans_a.len(), 1);
        let exempts_a = list(&store, MaskKind::Exempt, Some(chan_a)).unwrap();
        assert_eq!(exempts_a.len(), 1);
        let global_bans = list(&store, MaskKind::Ban, None).unwrap();
        assert_eq!(global_bans.len(), 1);
    }

    #[test]
    fn match_ban_returns_first_matching_channel_or_global_ban() {
        let store = fresh_store();
        let chan = make_channel(&store, "#x");
        insert(
            &store,
            &NewMask {
                kind: MaskKind::Ban,
                channel_id: Some(chan),
                mask: "*!*@bad.example".into(),
                reason: None,
                set_by: None,
                expires_at: None,
                sticky: false,
            },
            "node-a",
        )
        .unwrap();
        assert!(match_ban(&store, chan, "evil!u@bad.example")
            .unwrap()
            .is_some());
        assert!(match_ban(&store, chan, "alice!u@trusted.example")
            .unwrap()
            .is_none());
    }

    #[test]
    fn match_ban_respects_exempts() {
        let store = fresh_store();
        let chan = make_channel(&store, "#x");
        insert(
            &store,
            &NewMask {
                kind: MaskKind::Ban,
                channel_id: Some(chan),
                mask: "*!*@bad.example".into(),
                reason: None,
                set_by: None,
                expires_at: None,
                sticky: false,
            },
            "node-a",
        )
        .unwrap();
        insert(
            &store,
            &NewMask {
                kind: MaskKind::Exempt,
                channel_id: Some(chan),
                mask: "alice!*@*".into(),
                reason: None,
                set_by: None,
                expires_at: None,
                sticky: false,
            },
            "node-a",
        )
        .unwrap();
        // alice would match the ban host, but the exempt covers her.
        assert!(match_ban(&store, chan, "alice!u@bad.example")
            .unwrap()
            .is_none());
        // someone else still gets caught by the ban.
        assert!(match_ban(&store, chan, "eve!u@bad.example")
            .unwrap()
            .is_some());
    }

    #[test]
    fn glob_match_handles_star_question_and_case() {
        assert!(irc_glob_match("*", "anything"));
        assert!(irc_glob_match("*!*@*", "alice!user@host"));
        assert!(irc_glob_match("?lice!*@*", "alice!u@h"));
        assert!(irc_glob_match("*@H?ST.example", "x!u@HOST.example"));
        assert!(!irc_glob_match("alice!*", "BOB!u@h"));
    }

    #[test]
    fn delete_removes_mask() {
        let store = fresh_store();
        let chan = make_channel(&store, "#x");
        let nm = NewMask {
            kind: MaskKind::Ban,
            channel_id: Some(chan),
            mask: "*!*@x".into(),
            reason: None,
            set_by: None,
            expires_at: None,
            sticky: false,
        };
        let mask = insert(&store, &nm, "node-a").unwrap();
        assert!(delete(&store, mask.id).unwrap());
        assert!(get_by_id(&store, mask.id).unwrap().is_none());
    }
}
