//! Shade mTLS mesh.
//!
//! Listener and dialer for peer connections, the `PeerHello` handshake,
//! and the snapshot + delta gossip sync model with last-write-wins
//! resolution. Wire types come from `shade-proto`; persistence comes
//! from `shade-store`.
//!
//! At this milestone (M4 in progress) the async length-prefixed frame
//! codec lands first; the mTLS listener / dialer, handshake, and gossip
//! loops follow.

pub mod codec;

pub use codec::{read_frame, write_frame, CodecError, DEFAULT_MAX_FRAME_BYTES};
