//! Shade domain model.
//!
//! Pure types — `User`, `Channel`, `Mask`, `Role`, `FlagSet`, audit records —
//! shared by `shade-api`, `shade-mesh`, and `shade-store`. No I/O lives here.
//!
//! Wire format: serde with default field names. Time is Unix milliseconds.
//! IDs are 16-byte ULIDs (monotonic; sortable; round-trip through SQLite
//! as `BLOB`).

pub mod audit;
pub mod auth_token;
pub mod channel;
pub mod cookies;
pub mod flags;
pub mod mask;
pub mod password;
pub mod role;
pub mod role_assignment;
pub mod time;
pub mod user;

pub use audit::{AuditEntry, AuditId, AuditSource};
pub use auth_token::{AuthToken, AuthTokenError, AuthTokenHash, DEFAULT_TTL_MS, TOKEN_BYTES};
pub use channel::{Channel, ChannelId, ChannelSettings, ChannelUserFlags, NewChannel};
pub use cookies::{derive_channel_key, Cookie, CookieError, ReplayGuard};
pub use flags::{FlagSet, FlagSetParseError};
pub use mask::{Mask, MaskId, MaskKind, NewMask};
pub use password::{hash as hash_password, verify as verify_password, PasswordError};
pub use role::{slots_for, Role, ROLE_COUNTS};
pub use role_assignment::{compute_assignment, holds_role};
pub use time::now_ms;
pub use user::{NewUser, User, UserId};
