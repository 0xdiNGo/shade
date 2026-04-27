//! Audit log accessors. Insert-only — audit rows are never updated, and
//! cross-node history is reconstructed by pulling from each node
//! separately rather than mesh-replicating.

use rusqlite::{params, OptionalExtension};
use shade_core::{AuditEntry, AuditId, AuditSource};

use crate::{Store, StoreError};

/// Insert one audit entry. Returns the row as written.
pub fn insert(store: &Store, entry: &AuditEntry) -> Result<AuditEntry, StoreError> {
    let conn = store.conn()?;
    conn.execute(
        "INSERT INTO audit_log (id, ts, actor, action, target, details, source)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            entry.id.as_bytes().to_vec(),
            entry.ts,
            &entry.actor,
            &entry.action,
            &entry.target,
            serde_json::to_string(&entry.details).unwrap_or_else(|_| "null".into()),
            audit_source_str(entry.source),
        ],
    )?;
    Ok(entry.clone())
}

/// Look up an entry by id.
pub fn get_by_id(store: &Store, id: AuditId) -> Result<Option<AuditEntry>, StoreError> {
    let conn = store.conn()?;
    let row = conn
        .query_row(
            "SELECT id, ts, actor, action, target, details, source
             FROM audit_log
             WHERE id = ?1",
            params![id.as_bytes().to_vec()],
            |row| Ok(map_row(row)),
        )
        .optional()?;
    Ok(row)
}

/// List the most recent `limit` entries (oldest-first within the page),
/// optionally filtered by an `actor` substring match.
pub fn list_recent(
    store: &Store,
    limit: usize,
    actor: Option<&str>,
) -> Result<Vec<AuditEntry>, StoreError> {
    let conn = store.conn()?;
    let rows = if let Some(actor) = actor {
        let pattern = format!("%{actor}%");
        let mut stmt = conn.prepare(
            "SELECT id, ts, actor, action, target, details, source
             FROM audit_log
             WHERE actor LIKE ?1
             ORDER BY ts DESC
             LIMIT ?2",
        )?;
        let rows: Vec<AuditEntry> = stmt
            .query_map(
                params![pattern, i64::try_from(limit).unwrap_or(i64::MAX)],
                |row| Ok(map_row(row)),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, ts, actor, action, target, details, source
             FROM audit_log
             ORDER BY ts DESC
             LIMIT ?1",
        )?;
        let rows: Vec<AuditEntry> = stmt
            .query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
                Ok(map_row(row))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    Ok(rows)
}

fn audit_source_str(source: AuditSource) -> &'static str {
    match source {
        AuditSource::Api => "api",
        AuditSource::Irc => "irc",
        AuditSource::Mesh => "mesh",
        AuditSource::System => "system",
    }
}

fn map_row(row: &rusqlite::Row<'_>) -> AuditEntry {
    let id_bytes: Vec<u8> = row.get(0).unwrap();
    let mut id_arr = [0u8; 16];
    id_arr.copy_from_slice(&id_bytes[..16]);
    let details_text: String = row.get(5).unwrap();
    let details = serde_json::from_str(&details_text).unwrap_or(serde_json::Value::Null);
    let source_text: String = row.get(6).unwrap();
    let source = match source_text.as_str() {
        "api" => AuditSource::Api,
        "irc" => AuditSource::Irc,
        "mesh" => AuditSource::Mesh,
        _ => AuditSource::System,
    };
    AuditEntry {
        id: AuditId::from_bytes(id_arr),
        ts: row.get(1).unwrap(),
        actor: row.get(2).unwrap(),
        action: row.get(3).unwrap(),
        target: row.get(4).unwrap(),
        details,
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shade_core::now_ms;

    fn fresh_store() -> Store {
        let store = Store::open_in_memory().expect("open store");
        store.migrate().expect("migrate");
        store
    }

    #[test]
    fn insert_then_round_trip() {
        let store = fresh_store();
        let entry = AuditEntry::new(now_ms(), "@alice", "user.create", AuditSource::Api)
            .with_target("@bob")
            .with_details(serde_json::json!({"role": "user"}));
        let written = insert(&store, &entry).unwrap();
        let read = get_by_id(&store, written.id).unwrap().unwrap();
        assert_eq!(read.actor, "@alice");
        assert_eq!(read.action, "user.create");
        assert_eq!(read.target.as_deref(), Some("@bob"));
        assert_eq!(read.details["role"], "user");
        assert_eq!(read.source, AuditSource::Api);
    }

    #[test]
    fn list_recent_orders_newest_first() {
        let store = fresh_store();
        for i in 0..5 {
            let entry = AuditEntry {
                ts: 1_000 + i,
                ..AuditEntry::new(0, "system", "tick", AuditSource::System)
            };
            insert(&store, &entry).unwrap();
        }
        let rows = list_recent(&store, 3, None).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows[0].ts >= rows[1].ts);
        assert!(rows[1].ts >= rows[2].ts);
    }

    #[test]
    fn list_recent_filters_by_actor_substring() {
        let store = fresh_store();
        for actor in ["@alice", "@alice", "@bob"] {
            insert(
                &store,
                &AuditEntry::new(now_ms(), actor, "x", AuditSource::Api),
            )
            .unwrap();
        }
        let alice_rows = list_recent(&store, 100, Some("alice")).unwrap();
        assert_eq!(alice_rows.len(), 2);
    }
}
