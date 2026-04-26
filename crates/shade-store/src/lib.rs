//! Shade persistent store.
//!
//! SQLite (bundled) connection pool and refinery-managed migrations. Every
//! replicated table carries `(updated_at, origin_node)` so gossip can resolve
//! conflicts via last-write-wins. Repositories expose typed access for the
//! API and mesh layers.
