-- Bearer auth tokens for the admin API. See `shade_core::auth_token`.
--
-- Stored at rest as the SHA-256 of the secret, so a leaked row can't
-- be reused by an attacker without inverting SHA-256. Lookups hash the
-- presented bearer with the same function before SELECTing.
--
-- `handle` is the User.handle the token authorises as — the audit
-- actor for any request authenticated with this token. Not foreign-
-- keyed to `users(handle)` so the token survives a handle rename
-- (rare; operationally we'd revoke + re-issue anyway).
--
-- Intentionally NOT mesh-replicated. Tokens are local-only credentials
-- minted by the operator-facing node; replicating them would broaden
-- the blast radius of any single-node compromise.
CREATE TABLE auth_tokens (
    hash        BLOB PRIMARY KEY,
    handle      TEXT NOT NULL,
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    origin_node TEXT NOT NULL
) WITHOUT ROWID;

CREATE INDEX idx_auth_tokens_handle  ON auth_tokens(handle);
CREATE INDEX idx_auth_tokens_expires ON auth_tokens(expires_at);
