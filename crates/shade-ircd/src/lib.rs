//! Shade IRC client.
//!
//! Hand-rolled IRCv3-aware client: zero-copy line parser, capability
//! negotiation, SASL (PLAIN and EXTERNAL), batched mode queue, and in-memory
//! channel/member state. Connects over TLS only.
//!
//! The full client is wired up: parser, connection runner, capability
//! negotiation, SASL encoding, batched mode queue, channel state machine,
//! and the [`session`] async loop that ties them together.

pub mod caps;
pub mod connection;
pub mod message;
pub mod mode_queue;
pub mod parser;
pub mod rate_limit;
pub mod sasl;
pub mod session;
pub mod state;

pub use caps::{CapAction, CapNegotiation};
pub use connection::{
    BackoffConfig, Connection, ConnectionConfig, ConnectionEvent, SendError, TlsMode,
    WriteRateConfig, Writer,
};
pub use message::{Command, Message, ParseError, Tags};
pub use mode_queue::{Direction, ModeChange, ModeQueue, Priority, QueueKind};
pub use parser::{parse, parse_str};
pub use sasl::{authenticate_start, sasl_authenticate_lines, SaslMechanism};
pub use session::{ReadyHandle, Session, SessionConfig, SessionEvent};
pub use state::{ChannelState, Member, PrefixMap, ServerState, StateEvent};
