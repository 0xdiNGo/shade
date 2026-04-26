//! Shade mTLS mesh.
//!
//! Listener and dialer for peer connections, the `PeerHello` handshake, and
//! the snapshot + delta gossip sync model with last-write-wins resolution.
//! Wire types come from `shade-proto`; persistence comes from `shade-store`.
