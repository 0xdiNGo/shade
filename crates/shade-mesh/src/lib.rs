//! Shade mTLS mesh.
//!
//! Listener and dialer for peer connections, the `PeerHello` handshake,
//! and the snapshot + delta gossip sync model with last-write-wins
//! resolution. Wire types come from `shade-proto`; persistence comes
//! from `shade-store`.
//!
//! M4 layers, bottom to top:
//!
//! * [`codec`] — async length-prefixed MessagePack frame I/O over any
//!   `AsyncRead+AsyncWrite` stream.
//! * [`tls`] — rustls config builders + Subject-CN/SAN extraction from
//!   peer certs.
//! * [`peer`] — mTLS listener / dialer that hands back a `PeerStream`
//!   carrying the peer's claimed node identity.
//! * [`handshake`] — `PeerHello` exchange with version + identity-
//!   binding checks.
//!
//! Snapshot + delta gossip and the wire-up to `shade-store` ship in a
//! follow-up PR.

pub mod codec;
pub mod handshake;
pub mod peer;
pub mod tls;

pub use codec::{read_frame, write_frame, CodecError, DEFAULT_MAX_FRAME_BYTES};
pub use handshake::{run_handshake, HandshakeError};
pub use peer::{accept_peer, dial_peer, PeerError, PeerStream};
pub use tls::{cert_node_id, client_config, server_config, TlsConfigError};
