//! Shade HTTP+JSON admin API.
//!
//! axum router for users, channels, flags, masks, peers, roles, and audit log.
//! Authentication is mTLS client cert; the subject CN maps to a Shade user
//! handle. OpenAPI is generated from the route handlers.
