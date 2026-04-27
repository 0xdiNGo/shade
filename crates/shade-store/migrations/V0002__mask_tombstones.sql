-- Shade schema, version 0002.
--
-- Mask delete tombstones for LWW gossip. When a node deletes a mask the
-- corresponding row in `masklists` is removed and a row is inserted here
-- carrying (deleted_at, origin_node). On inbound mesh frames:
--
--   * An incoming Mask Upsert is ignored if a tombstone exists with
--     `deleted_at > excluded.updated_at`, OR equal time + lex-smaller
--     origin_node — same LWW rule the upsert paths use.
--   * An incoming Mask Delete replaces an existing tombstone if it's
--     newer; older tombstones are kept.
--
-- Wraith's add/remove tombstone scheme is documented in
-- `src/mod/share.mod/share.cc:712-820` (handlers for `+ms`, `-ms`, etc.).
-- We use the same shape but a typed table instead of in-memory linked
-- lists.

CREATE TABLE mask_tombstones (
    id          BLOB    PRIMARY KEY,
    deleted_at  INTEGER NOT NULL,
    origin_node TEXT    NOT NULL
);
