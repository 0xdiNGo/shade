//! Parsed IRC message representation.
//!
//! [`Message`] borrows directly from the input buffer; nothing is allocated
//! per-message except the `Vec<&str>` of parameters. Callers that need owned
//! data should clone the relevant `&str` slices into `String`s themselves.

use std::fmt;

/// A parsed IRC message.
///
/// Lifetime `'a` is the lifetime of the input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    /// IRCv3 message tags. Empty if the line had no `@tags ` prefix.
    pub tags: Tags<'a>,
    /// The raw source/prefix string, e.g. `"nick!user@host"` or `"server.example"`.
    /// `None` if the line had no `:source ` prefix.
    pub source: Option<&'a str>,
    /// Either a textual command (`PRIVMSG`, `JOIN`) or a 3-digit numeric reply.
    pub command: Command<'a>,
    /// Ordered parameters. The trailing `:param-with-spaces` (if any) is the
    /// last element; the parser does not preserve the leading colon, since
    /// re-serialization can re-derive it from content (any param with spaces
    /// or starting empty must be trailing).
    pub params: Vec<&'a str>,
}

impl<'a> Message<'a> {
    /// Convenience: case-insensitive command match on a textual command.
    /// Always returns `false` for numeric commands.
    #[must_use]
    pub fn is_command(&self, cmd: &str) -> bool {
        match self.command {
            Command::Word(w) => w.eq_ignore_ascii_case(cmd),
            Command::Numeric(_) => false,
        }
    }

    /// Convenience: numeric command match.
    #[must_use]
    pub fn is_numeric(&self, n: u16) -> bool {
        matches!(self.command, Command::Numeric(m) if m == n)
    }

    /// Convenience: parameter at index, or `None`.
    #[must_use]
    pub fn param(&self, idx: usize) -> Option<&'a str> {
        self.params.get(idx).copied()
    }
}

/// Either a textual command word or a 3-digit numeric reply code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command<'a> {
    /// Textual command, e.g. `PRIVMSG`, `JOIN`, `CAP`, `AUTHENTICATE`.
    Word(&'a str),
    /// Numeric reply (1..=999), e.g. 001 RPL_WELCOME, 353 RPL_NAMREPLY.
    Numeric(u16),
}

impl fmt::Display for Command<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Word(s) => f.write_str(s),
            Self::Numeric(n) => write!(f, "{n:03}"),
        }
    }
}

/// IRCv3 message tags. Construct from the raw `@…` segment via [`Tags::new`]
/// (parser-internal); end-users iterate via [`Tags::iter`] or look up by key
/// via [`Tags::raw_get`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tags<'a> {
    raw: &'a str,
}

impl<'a> Tags<'a> {
    pub(crate) fn new(raw: &'a str) -> Self {
        Self { raw }
    }

    /// Underlying raw `key=value;key2;key3=value3` string.
    #[must_use]
    pub fn raw(&self) -> &'a str {
        self.raw
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Iterate `(key, value)` pairs. Bare `key` (no `=`) yields `(key, None)`.
    /// Tag values are returned **un-decoded**: IRCv3 escape sequences
    /// (`\:`, `\s`, `\\`, `\r`, `\n`) are not unescaped here. Most consumers
    /// don't need decoding (e.g. `account=foo`); for those that do, use
    /// [`decode_tag_value`].
    #[must_use]
    pub fn iter(&self) -> TagsIter<'a> {
        TagsIter { rest: self.raw }
    }

    /// Look up a tag by key. Returns:
    /// - `None` if the key is absent
    /// - `Some(None)` if the key is present with no value (`key`)
    /// - `Some(Some(v))` if the key is present with a value (`key=v`)
    #[must_use]
    pub fn raw_get(&self, key: &str) -> Option<Option<&'a str>> {
        self.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }
}

impl<'a> IntoIterator for &Tags<'a> {
    type Item = (&'a str, Option<&'a str>);
    type IntoIter = TagsIter<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over the (key, optional-value) pairs of a [`Tags`] block.
#[derive(Debug, Clone)]
pub struct TagsIter<'a> {
    rest: &'a str,
}

impl<'a> Iterator for TagsIter<'a> {
    type Item = (&'a str, Option<&'a str>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.rest.is_empty() {
                return None;
            }
            let (kv, after) = match self.rest.split_once(';') {
                Some((kv, after)) => (kv, after),
                None => (self.rest, ""),
            };
            self.rest = after;
            if kv.is_empty() {
                continue; // skip empty entries from leading/doubled separators
            }
            let entry = match kv.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (kv, None),
            };
            return Some(entry);
        }
    }
}

/// Decode IRCv3 message-tag value escapes:
/// `\:` → `;`, `\s` → ` `, `\\` → `\`, `\r` → `\r`, `\n` → `\n`.
/// A trailing lone `\` is dropped (per spec). Returns the original slice if
/// no escapes are present.
#[must_use]
pub fn decode_tag_value(value: &str) -> std::borrow::Cow<'_, str> {
    if !value.contains('\\') {
        return std::borrow::Cow::Borrowed(value);
    }
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(':') => out.push(';'),
            Some('s') => out.push(' '),
            Some('\\') => out.push('\\'),
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some(other) => out.push(other), // unknown escape: keep the char
            None => {}                      // trailing backslash: drop per spec
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Errors produced by [`crate::parse`] / [`crate::parse_str`].
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    /// Empty line (after stripping trailing CRLF).
    #[error("empty line")]
    Empty,
    /// Input bytes were not valid UTF-8.
    #[error("not valid UTF-8")]
    NotUtf8,
    /// `@tags` segment with no following space-delimited command.
    #[error("missing space after tags")]
    TagsTruncated,
    /// `:source` segment with no following space-delimited command.
    #[error("missing space after source")]
    SourceTruncated,
    /// Tags and/or source were present but no command followed.
    #[error("missing command")]
    MissingCommand,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_display_word() {
        assert_eq!(format!("{}", Command::Word("PRIVMSG")), "PRIVMSG");
    }

    #[test]
    fn command_display_numeric_zero_pads() {
        assert_eq!(format!("{}", Command::Numeric(1)), "001");
        assert_eq!(format!("{}", Command::Numeric(353)), "353");
    }

    #[test]
    fn tags_iter_skips_empty_entries() {
        let t = Tags::new("a;;b");
        let collected: Vec<_> = t.iter().collect();
        assert_eq!(collected, vec![("a", None), ("b", None)]);
    }

    #[test]
    fn tags_iter_handles_kv_and_bare() {
        let t = Tags::new("account=foo;bar;time=1");
        let collected: Vec<_> = t.iter().collect();
        assert_eq!(
            collected,
            vec![("account", Some("foo")), ("bar", None), ("time", Some("1"))]
        );
    }

    #[test]
    fn tags_value_with_equals_keeps_remainder() {
        let t = Tags::new("k=a=b=c");
        assert_eq!(t.raw_get("k"), Some(Some("a=b=c")));
    }

    #[test]
    fn tags_raw_get_distinguishes_absence_from_no_value() {
        let t = Tags::new("k1;k2=v");
        assert_eq!(t.raw_get("k1"), Some(None));
        assert_eq!(t.raw_get("k2"), Some(Some("v")));
        assert_eq!(t.raw_get("missing"), None);
    }

    #[test]
    fn decode_tag_value_no_escapes_borrows() {
        let v = decode_tag_value("hello world");
        assert!(matches!(v, std::borrow::Cow::Borrowed(_)));
        assert_eq!(v, "hello world");
    }

    #[test]
    fn decode_tag_value_handles_each_escape() {
        assert_eq!(decode_tag_value(r"a\:b"), "a;b");
        assert_eq!(decode_tag_value(r"a\sb"), "a b");
        assert_eq!(decode_tag_value(r"a\\b"), "a\\b");
        assert_eq!(decode_tag_value(r"a\rb"), "a\rb");
        assert_eq!(decode_tag_value(r"a\nb"), "a\nb");
    }

    #[test]
    fn decode_tag_value_drops_trailing_backslash() {
        assert_eq!(decode_tag_value(r"abc\"), "abc");
    }

    #[test]
    fn decode_tag_value_unknown_escape_keeps_char() {
        assert_eq!(decode_tag_value(r"a\xb"), "axb");
    }
}
