//! Shade IRC client.
//!
//! Hand-rolled IRCv3-aware client: zero-copy line parser, capability
//! negotiation, SASL (PLAIN and EXTERNAL), batched mode queue, and in-memory
//! channel/member state. Connects over TLS only.
//!
//! At this milestone the parser and connection runner are wired up; caps,
//! SASL, channel state, and the mode queue land in subsequent PRs.

pub mod connection;
pub mod message;
pub mod parser;
pub mod rate_limit;

pub use connection::{
    BackoffConfig, Connection, ConnectionConfig, ConnectionEvent, SendError, TlsMode,
    WriteRateConfig, Writer,
};
pub use message::{Command, Message, ParseError, Tags};
pub use parser::{parse, parse_str};
