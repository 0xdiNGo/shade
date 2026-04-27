//! Zero-copy IRC line parser.
//!
//! Accepts both raw bytes and `&str`. Strips a single optional `\r\n` or
//! `\n` terminator. Handles IRCv3 message tags, optional `:source` prefix,
//! a textual or 3-digit-numeric command, and space-separated parameters
//! with an optional `:trailing`.
//!
//! The parser intentionally does not enforce length bounds (RFC1459's 512
//! and IRCv3's 8191) — callers that care can check `input.len()` before or
//! after.

use crate::message::{Command, Message, ParseError, Tags};

/// Parse an IRC line from raw bytes.
pub fn parse(input: &[u8]) -> Result<Message<'_>, ParseError> {
    let line = std::str::from_utf8(input).map_err(|_| ParseError::NotUtf8)?;
    parse_str(line)
}

/// Parse an IRC line from a `&str`.
pub fn parse_str(line: &str) -> Result<Message<'_>, ParseError> {
    let line = strip_line_terminator(line);

    if line.is_empty() {
        return Err(ParseError::Empty);
    }

    let mut rest = line;

    // Tags: `@key=value;key;key=value `
    let tags = if let Some(after_at) = rest.strip_prefix('@') {
        let (tags_str, after_space) =
            split_first_space(after_at).ok_or(ParseError::TagsTruncated)?;
        rest = trim_leading_spaces(after_space);
        Tags::new(tags_str)
    } else {
        Tags::default()
    };

    // Source: `:nick!user@host ` or `:server.name `
    let source = if let Some(after_colon) = rest.strip_prefix(':') {
        let (source_str, after_space) =
            split_first_space(after_colon).ok_or(ParseError::SourceTruncated)?;
        rest = trim_leading_spaces(after_space);
        Some(source_str)
    } else {
        None
    };

    if rest.is_empty() {
        return Err(ParseError::MissingCommand);
    }

    // Command + the start of params (may be "")
    let (cmd_str, params_part) = match split_first_space(rest) {
        Some((c, p)) => (c, trim_leading_spaces(p)),
        None => (rest, ""),
    };

    let command = parse_command(cmd_str)?;
    let params = parse_params(params_part);

    Ok(Message {
        tags,
        source,
        command,
        params,
    })
}

fn strip_line_terminator(line: &str) -> &str {
    if let Some(stripped) = line.strip_suffix("\r\n") {
        stripped
    } else if let Some(stripped) = line.strip_suffix('\n') {
        stripped
    } else {
        line
    }
}

fn split_first_space(s: &str) -> Option<(&str, &str)> {
    let idx = s.find(' ')?;
    Some((&s[..idx], &s[idx + 1..]))
}

fn trim_leading_spaces(s: &str) -> &str {
    s.trim_start_matches(' ')
}

fn parse_command(s: &str) -> Result<Command<'_>, ParseError> {
    if s.is_empty() {
        return Err(ParseError::MissingCommand);
    }
    if s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()) {
        let n: u16 = s.parse().expect("3 ascii digits parses as u16");
        return Ok(Command::Numeric(n));
    }
    Ok(Command::Word(s))
}

fn parse_params(input: &str) -> Vec<&str> {
    let mut params = Vec::new();
    let mut rest = input;

    while !rest.is_empty() {
        // Trailing parameter: leading colon means "rest of line, may contain spaces".
        if let Some(trailing) = rest.strip_prefix(':') {
            params.push(trailing);
            break;
        }
        if let Some((param, after)) = split_first_space(rest) {
            if !param.is_empty() {
                params.push(param);
            }
            rest = trim_leading_spaces(after);
        } else {
            // No more spaces; remaining is one param.
            params.push(rest);
            break;
        }
    }

    params
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Command;

    #[test]
    fn ping_with_trailing() {
        let m = parse_str("PING :server.example\r\n").unwrap();
        assert_eq!(m.command, Command::Word("PING"));
        assert_eq!(m.params, vec!["server.example"]);
        assert!(m.source.is_none());
        assert!(m.tags.is_empty());
    }

    #[test]
    fn privmsg_with_source_and_trailing() {
        let m = parse_str(":nick!user@host PRIVMSG #chan :hello world\r\n").unwrap();
        assert_eq!(m.source, Some("nick!user@host"));
        assert_eq!(m.command, Command::Word("PRIVMSG"));
        assert_eq!(m.params, vec!["#chan", "hello world"]);
    }

    #[test]
    fn numeric_001_welcome() {
        let m = parse_str(":server.example 001 myNick :Welcome to the network").unwrap();
        assert!(m.is_numeric(1));
        assert_eq!(m.command, Command::Numeric(1));
        assert_eq!(m.params, vec!["myNick", "Welcome to the network"]);
    }

    #[test]
    fn ircv3_tags_with_source_and_command() {
        let m = parse_str(
            "@time=2025-01-01T00:00:00.000Z;account=foo \
             :nick!user@host JOIN #chan",
        )
        .unwrap();
        assert_eq!(
            m.tags.raw_get("time"),
            Some(Some("2025-01-01T00:00:00.000Z"))
        );
        assert_eq!(m.tags.raw_get("account"), Some(Some("foo")));
        assert_eq!(m.source, Some("nick!user@host"));
        assert!(m.is_command("join"));
        assert_eq!(m.params, vec!["#chan"]);
    }

    #[test]
    fn empty_trailing_param() {
        let m = parse_str("PRIVMSG #c :").unwrap();
        assert_eq!(m.params, vec!["#c", ""]);
    }

    #[test]
    fn no_trailing_param() {
        let m = parse_str("PRIVMSG #c").unwrap();
        assert_eq!(m.params, vec!["#c"]);
    }

    #[test]
    fn bare_tag_no_value() {
        let m = parse_str("@empty PING :s").unwrap();
        assert_eq!(m.tags.raw_get("empty"), Some(None));
        assert_eq!(m.command, Command::Word("PING"));
        assert_eq!(m.params, vec!["s"]);
    }

    #[test]
    fn server_source_no_user_host() {
        let m = parse_str(":server.foo NOTICE * :Hello there").unwrap();
        assert_eq!(m.source, Some("server.foo"));
        assert_eq!(m.command, Command::Word("NOTICE"));
        assert_eq!(m.params, vec!["*", "Hello there"]);
    }

    #[test]
    fn collapses_runs_of_spaces_between_segments() {
        // RFC says params are separated by single spaces, but real-world
        // implementations sometimes pad. We collapse cosmetic whitespace
        // between major segments and between space-separated params, but
        // a leading colon still starts trailing.
        let m = parse_str(":src   PRIVMSG   #c   hello   :trailing").unwrap();
        assert_eq!(m.source, Some("src"));
        assert_eq!(m.command, Command::Word("PRIVMSG"));
        assert_eq!(m.params, vec!["#c", "hello", "trailing"]);
    }

    #[test]
    fn cap_ls_with_trailing() {
        let m = parse_str(":server CAP * LS :sasl server-time multi-prefix").unwrap();
        assert_eq!(m.command, Command::Word("CAP"));
        assert_eq!(m.params, vec!["*", "LS", "sasl server-time multi-prefix"]);
    }

    #[test]
    fn lone_lf_terminator() {
        let m = parse_str("PING :s\n").unwrap();
        assert_eq!(m.command, Command::Word("PING"));
    }

    #[test]
    fn no_terminator_is_fine() {
        let m = parse_str("PING :s").unwrap();
        assert_eq!(m.command, Command::Word("PING"));
    }

    #[test]
    fn err_empty() {
        assert_eq!(parse_str("").unwrap_err(), ParseError::Empty);
        assert_eq!(parse_str("\r\n").unwrap_err(), ParseError::Empty);
        assert_eq!(parse_str("\n").unwrap_err(), ParseError::Empty);
    }

    #[test]
    fn err_tags_truncated() {
        assert_eq!(parse_str("@a").unwrap_err(), ParseError::TagsTruncated);
        assert_eq!(parse_str("@k=v").unwrap_err(), ParseError::TagsTruncated);
    }

    #[test]
    fn err_source_truncated() {
        assert_eq!(parse_str(":src").unwrap_err(), ParseError::SourceTruncated);
    }

    #[test]
    fn err_missing_command_after_tags() {
        // "@a " parses tags=a, then rest=""; that's missing command.
        assert_eq!(parse_str("@a ").unwrap_err(), ParseError::MissingCommand);
    }

    #[test]
    fn err_missing_command_after_source() {
        assert_eq!(parse_str(":src ").unwrap_err(), ParseError::MissingCommand);
    }

    #[test]
    fn err_not_utf8_via_bytes_api() {
        let bad = [0xff, 0xfe, b'\r', b'\n'];
        assert_eq!(parse(&bad).unwrap_err(), ParseError::NotUtf8);
    }

    #[test]
    fn message_helpers() {
        let m = parse_str("PRIVMSG #c :hello").unwrap();
        assert!(m.is_command("PRIVMSG"));
        assert!(m.is_command("privmsg")); // case-insensitive
        assert!(!m.is_command("NOTICE"));
        assert!(!m.is_numeric(1));
        assert_eq!(m.param(0), Some("#c"));
        assert_eq!(m.param(1), Some("hello"));
        assert_eq!(m.param(2), None);
    }

    // ---- Property tests --------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        /// The parser must never panic on any byte input. ParseError is the
        /// expected failure mode; no `unwrap`-ish panics, no slice-bounds
        /// issues, no UTF-8 surprises.
        #[test]
        fn parse_does_not_panic_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse(&bytes);
        }

        /// Any valid printable ASCII line either parses or returns an error,
        /// and never panics.
        #[test]
        fn parse_does_not_panic_on_printable_ascii(s in "[\x20-\x7e]{0,256}") {
            let _ = parse_str(&s);
        }

        /// When the parser succeeds, the command field is always non-empty
        /// (textual command is non-empty by construction; numeric is `u16`).
        #[test]
        fn command_is_non_empty_on_success(s in "[\x20-\x7e]{1,256}") {
            if let Ok(m) = parse_str(&s) {
                match m.command {
                    Command::Word(w) => prop_assert!(!w.is_empty()),
                    Command::Numeric(_) => {}
                }
            }
        }
    }
}
