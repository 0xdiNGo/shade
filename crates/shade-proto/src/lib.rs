//! Mesh wire types and version negotiation for the Shade botnet.
//!
//! Frames are length-prefixed MessagePack messages exchanged over mTLS streams
//! between Shade nodes. This crate is intentionally I/O-free; transport and
//! peer state live in `shade-mesh`.
