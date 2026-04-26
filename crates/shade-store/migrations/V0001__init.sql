-- Shade schema, version 0001.
--
-- Every replicated table carries (updated_at, origin_node) so gossip can
-- resolve concurrent writes via last-write-wins.
--
-- IDs are 16-byte ULIDs stored as BLOB. Time is stored as Unix milliseconds
-- (INTEGER). Booleans are 0/1 INTEGER per SQLite convention.

CREATE TABLE users (
    id            BLOB    PRIMARY KEY,
    handle        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT,
    is_bot        INTEGER NOT NULL DEFAULT 0,
    global_flags  INTEGER NOT NULL DEFAULT 0,
    comment       TEXT,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    last_seen_at  INTEGER,
    origin_node   TEXT    NOT NULL
);

CREATE TABLE user_hosts (
    user_id  BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hostmask TEXT NOT NULL,
    PRIMARY KEY (user_id, hostmask)
);

CREATE TABLE channels (
    id          BLOB    PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    origin_node TEXT    NOT NULL
);

CREATE TABLE channel_settings (
    channel_id  BLOB    PRIMARY KEY REFERENCES channels(id) ON DELETE CASCADE,
    flags       INTEGER NOT NULL DEFAULT 0,
    flood_json  TEXT    NOT NULL DEFAULT '{}',
    mode_pls    TEXT    NOT NULL DEFAULT '',
    mode_mns    TEXT    NOT NULL DEFAULT '',
    limit_prot  INTEGER,
    key_prot    TEXT,
    topic_saved TEXT,
    updated_at  INTEGER NOT NULL,
    origin_node TEXT    NOT NULL
);

CREATE TABLE channel_user_flags (
    channel_id  BLOB    NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    user_id     BLOB    NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    flags       INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL,
    origin_node TEXT    NOT NULL,
    PRIMARY KEY (channel_id, user_id)
);

-- Unified ban / exempt / invite list. kind: 1=ban, 2=exempt, 3=invite.
-- channel_id NULL => global mask (network-wide enforcement).
CREATE TABLE masklists (
    id          BLOB    PRIMARY KEY,
    kind        INTEGER NOT NULL,
    channel_id  BLOB    REFERENCES channels(id) ON DELETE CASCADE,
    mask        TEXT    NOT NULL,
    reason      TEXT,
    set_by      TEXT,
    set_at      INTEGER NOT NULL,
    expires_at  INTEGER,
    sticky      INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL,
    origin_node TEXT    NOT NULL,
    UNIQUE (kind, channel_id, mask)
);

CREATE INDEX masklist_chan_idx ON masklists(channel_id, kind);

CREATE TABLE peers (
    node_id  TEXT    PRIMARY KEY,
    cert_fpr TEXT    NOT NULL,
    endpoint TEXT    NOT NULL,
    added_at INTEGER NOT NULL,
    notes    TEXT
);

-- Runtime cache of the last computed role assignment per channel. Not
-- authoritative; deterministic rebalance recomputes on topology change.
CREATE TABLE role_assignments (
    channel_id BLOB    NOT NULL,
    role       INTEGER NOT NULL,
    node_id    TEXT    NOT NULL,
    generation INTEGER NOT NULL,
    PRIMARY KEY (channel_id, role, node_id)
);

CREATE TABLE audit_log (
    id      BLOB    PRIMARY KEY,
    ts      INTEGER NOT NULL,
    actor   TEXT    NOT NULL,
    action  TEXT    NOT NULL,
    target  TEXT,
    details TEXT,
    source  TEXT    NOT NULL
);

CREATE INDEX audit_ts_idx ON audit_log(ts);
