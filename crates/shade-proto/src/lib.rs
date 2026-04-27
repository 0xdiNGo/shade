//! Mesh wire types and version negotiation for the Shade botnet.
//!
//! Frames are length-prefixed MessagePack messages exchanged over mTLS streams
//! between Shade nodes. This crate is intentionally I/O-free; transport and
//! peer state live in `shade-mesh`.
//!
//! Wire model:
//!
//! ```text
//!   ┌─ frame on the wire ────────────────────────────────────────┐
//!   │  u32 length (BE)  │  msgpack-encoded Frame enum (payload)  │
//!   └────────────────────────────────────────────────────────────┘
//! ```
//!
//! Length is the byte count of the payload only — it does not include the
//! 4-byte length header itself.
//!
//! All replicated rows carry `(updated_at, origin_node)`. The receiver
//! resolves conflicts last-write-wins: an inbound row replaces the local
//! row iff its `updated_at` is greater (ties broken by lex-smaller
//! `origin_node`). See `shade-store`'s upsert paths for the SQL.

pub mod frame;
pub mod handshake;
pub mod sync;

pub use frame::{Frame, FrameDecodeError};
pub use handshake::{Goodbye, PeerFeatures, PeerHello, PROTO_VERSION};
pub use sync::{
    Delete, DeleteKind, SnapshotChunk, SnapshotEntry, SnapshotRequest, Upsert, UpsertKind,
};

/// Encode a `Frame` to MessagePack bytes (no length prefix). The transport
/// layer in `shade-mesh` adds the prefix.
///
/// # Errors
/// Returns the underlying [`rmp_serde::encode::Error`] on serialization
/// failure (in practice only on I/O against a custom writer; in-memory
/// encoding does not fail for `Frame`).
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, rmp_serde::encode::Error> {
    rmp_serde::to_vec_named(frame)
}

/// Decode a `Frame` from MessagePack bytes (no length prefix).
///
/// # Errors
/// Returns [`FrameDecodeError::Decode`] for malformed bytes.
pub fn decode_frame(bytes: &[u8]) -> Result<Frame, FrameDecodeError> {
    rmp_serde::from_slice(bytes).map_err(FrameDecodeError::Decode)
}
