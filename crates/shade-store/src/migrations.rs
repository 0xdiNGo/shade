//! Embedded SQL migrations applied via [`refinery`].
//!
//! Migration files live in `migrations/` next to `Cargo.toml`. Files are
//! named `V<n>__<description>.sql`; refinery applies them in order and
//! tracks applied versions in its own bookkeeping table.

use refinery::embed_migrations;

embed_migrations!("./migrations");

pub use migrations::runner;
