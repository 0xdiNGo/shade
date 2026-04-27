//! Shade domain model.
//!
//! Pure types — `User`, `Channel`, `Mask`, `Role`, `FlagSet`, audit records —
//! shared by `shade-api`, `shade-mesh`, and `shade-store`. No I/O lives here.
//!
//! Wire format: serde with default field names. Time is Unix milliseconds.
//! IDs are 16-byte ULIDs (monotonic; sortable; round-trip through SQLite
//! as `BLOB`).

pub mod audit;
pub mod channel;
pub mod flags;
pub mod mask;
pub mod role;
pub mod time;
pub mod user;

pub use audit::{AuditEntry, AuditId, AuditSource};
pub use channel::{Channel, ChannelId, ChannelSettings, ChannelUserFlags, NewChannel};
pub use flags::{FlagSet, FlagSetParseError};
pub use mask::{Mask, MaskId, MaskKind, NewMask};
pub use role::{slots_for, Role, ROLE_COUNTS};
pub use time::now_ms;
pub use user::{NewUser, User, UserId};
