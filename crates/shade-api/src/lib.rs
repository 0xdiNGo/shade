//! Shade HTTP+JSON admin API.
//!
//! axum router for users, channels, flags, masks, peers, roles, and audit log.
//! Authentication is mTLS client cert; the subject CN maps to a Shade user
//! handle. OpenAPI is generated from the route handlers.
//!
//! At this stage, only the operational endpoints are wired up: `/healthz`,
//! `/readyz`, and `/metrics`. The CRUD surface lands in M3 once the domain
//! model and store are in place.

pub mod admin;
pub mod metrics;
pub mod v1;
