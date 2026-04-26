//! Shade IRC client.
//!
//! Hand-rolled IRCv3-aware client: zero-copy line parser, capability
//! negotiation, SASL (PLAIN and EXTERNAL), batched mode queue, and in-memory
//! channel/member state. Connects over TLS only.
