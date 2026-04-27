//! Shade IRC client.
//!
//! Hand-rolled IRCv3-aware client: zero-copy line parser, capability
//! negotiation, SASL (PLAIN and EXTERNAL), batched mode queue, and in-memory
//! channel/member state. Connects over TLS only.
//!
//! At this milestone only the parser is wired up; connection, caps, SASL,
//! state, and the mode queue land in subsequent PRs.

pub mod message;
pub mod parser;

pub use message::{Command, Message, ParseError, Tags};
pub use parser::{parse, parse_str};
