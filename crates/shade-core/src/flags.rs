//! Flag bitsets.
//!
//! A [`FlagSet`] is a `u64` bitmap where each lowercase letter `a..=z` and
//! each uppercase letter `A..=Z` maps to exactly one bit, leaving 12 bits
//! reserved. The mapping mirrors Wraith's `init_flags` at
//! `src/flags.cc:60-72` — lowercase fills bits 0..=25, uppercase fills bits
//! 26..=51 — but Shade exposes it as a typed wrapper rather than a global
//! `flag_t FLAG[128]`.
//!
//! Display and parse use the canonical Wraith-style notation, e.g. `+ox-d`,
//! optionally with a leading `+` (additions only) or `-` (removals only).
//! Unlike Wraith we always emit additions before removals when serializing
//! a freshly-built set, so equality of the textual form is a function of
//! the set, not insertion order.
//!
//! Example:
//!
//! ```
//! use shade_core::FlagSet;
//! let f: FlagSet = "+oxv".parse().unwrap();
//! assert!(f.contains_letter('o'));
//! assert_eq!(f.to_string(), "+ovx");
//! ```

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Letter-encoded flag bitmap.
///
/// Internal representation is `u64` so the type is `Copy`. The serde
/// representation is the human-readable Wraith-style diff string
/// (e.g. `"+ovx"` or `""` for the empty set), making API payloads
/// readable and CLI inputs natural. Storage code converts via
/// [`FlagSet::bits`] / [`FlagSet::from_bits`] when writing to SQLite's
/// `INTEGER` column, so the on-disk format stays compact.
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlagSet {
    bits: u64,
}

impl Serialize for FlagSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for FlagSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl FlagSet {
    /// Empty flag set.
    pub const NONE: Self = Self { bits: 0 };

    /// Build a [`FlagSet`] from raw bits. Use [`FlagSet::from_letters`] for
    /// the textual form.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self { bits }
    }

    /// Underlying bit pattern.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.bits
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Insert every letter in `letters`. Non-ASCII-letter characters are
    /// rejected with [`FlagSetParseError::InvalidChar`].
    pub fn from_letters(letters: &str) -> Result<Self, FlagSetParseError> {
        let mut s = Self::NONE;
        for c in letters.chars() {
            s.insert_letter(c)?;
        }
        Ok(s)
    }

    /// Insert one letter into the set.
    pub fn insert_letter(&mut self, c: char) -> Result<(), FlagSetParseError> {
        let bit = letter_bit(c).ok_or(FlagSetParseError::InvalidChar(c))?;
        self.bits |= bit;
        Ok(())
    }

    /// Remove one letter from the set.
    pub fn remove_letter(&mut self, c: char) -> Result<(), FlagSetParseError> {
        let bit = letter_bit(c).ok_or(FlagSetParseError::InvalidChar(c))?;
        self.bits &= !bit;
        Ok(())
    }

    /// Whether the letter is in the set.
    #[must_use]
    pub fn contains_letter(self, c: char) -> bool {
        letter_bit(c).is_some_and(|bit| self.bits & bit != 0)
    }

    /// Set union (`self | other`).
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Set intersection (`self & other`).
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }

    /// Set difference (`self & !other`).
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self {
            bits: self.bits & !other.bits,
        }
    }

    /// Whether every bit in `other` is also set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.bits & other.bits == other.bits
    }

    /// Iterate the letters present, in canonical order (lowercase a..z then
    /// uppercase A..Z).
    pub fn letters(self) -> impl Iterator<Item = char> {
        let bits = self.bits;
        (b'a'..=b'z').chain(b'A'..=b'Z').filter_map(move |b| {
            let c = b as char;
            let bit = letter_bit(c)?;
            (bits & bit != 0).then_some(c)
        })
    }

    /// Apply a Wraith-style diff string (`+ox-d`, `+o`, `-x`, etc.). Order
    /// matters: a later `-c` removes what an earlier `+c` added.
    pub fn apply_diff(&mut self, diff: &str) -> Result<(), FlagSetParseError> {
        let mut adding = true;
        for c in diff.chars() {
            match c {
                '+' => adding = true,
                '-' => adding = false,
                ' ' | '\t' => {}
                c => {
                    if adding {
                        self.insert_letter(c)?;
                    } else {
                        self.remove_letter(c)?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for FlagSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FlagSet({self})")
    }
}

impl fmt::Display for FlagSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("");
        }
        f.write_str("+")?;
        for c in self.letters() {
            f.write_str(&c.to_string())?;
        }
        Ok(())
    }
}

impl FromStr for FlagSet {
    type Err = FlagSetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut set = Self::NONE;
        set.apply_diff(s)?;
        Ok(set)
    }
}

impl std::ops::BitOr for FlagSet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl std::ops::BitAnd for FlagSet {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        self.intersection(rhs)
    }
}

/// Map a flag letter to its bit. `a..=z` go to bits 0..=25; `A..=Z` go to
/// bits 26..=51. Non-letters return `None`.
const fn letter_bit(c: char) -> Option<u64> {
    match c {
        'a'..='z' => Some(1u64 << ((c as u32 - 'a' as u32) as u64)),
        'A'..='Z' => Some(1u64 << (26 + (c as u32 - 'A' as u32) as u64)),
        _ => None,
    }
}

/// Parsing errors from [`FlagSet::from_letters`] / [`FlagSet::apply_diff`] /
/// [`FlagSet`]'s [`FromStr`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FlagSetParseError {
    /// A character that is neither an ASCII letter nor `+`/`-`.
    #[error("invalid flag character {0:?}")]
    InvalidChar(char),
}

// ----- canonical user flag letters ---------------------------------------
//
// Mirrors Wraith's `src/flags.h` user-flag macros. Names use the same
// terminology so the cross-reference is obvious. The Wraith-only flags we
// drop in v0 (party-line `p`, RESOLV, etc.) are simply omitted.

/// `o` — auto-op privileges on join (per-channel).
pub const USER_OP: char = 'o';
/// `O` — auto-op everywhere (global).
pub const USER_AUTOOP: char = 'O';
/// `d` — auto-deop / never op (per-channel).
pub const USER_DEOP: char = 'd';
/// `k` — auto-kick on join (per-channel).
pub const USER_KICK: char = 'k';
/// `q` — auto-devoice / never voice (per-channel).
pub const USER_QUIET: char = 'q';
/// `v` — auto-voice on join (per-channel).
pub const USER_VOICE: char = 'v';
/// `x` — exempt from flood detection (per-channel).
pub const USER_NOFLOOD: char = 'x';
/// `m` — channel master (admin within a channel scope).
pub const USER_MASTER: char = 'm';
/// `n` — owner (highest privilege; can edit other masters).
pub const USER_OWNER: char = 'n';
/// `a` — global admin (network-wide).
pub const USER_ADMIN: char = 'a';
/// `b` — bot account (treated specially by mesh + IRC client).
pub const USER_BOT: char = 'b';

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercase_a_through_z_pack_into_low_bits() {
        let set: FlagSet = "+abcdefghijklmnopqrstuvwxyz".parse().unwrap();
        assert_eq!(set.bits(), (1u64 << 26) - 1);
    }

    #[test]
    fn uppercase_a_through_z_pack_into_high_bits() {
        let set: FlagSet = "+ABCDEFGHIJKLMNOPQRSTUVWXYZ".parse().unwrap();
        // 26 bits set starting at bit 26.
        assert_eq!(set.bits(), ((1u64 << 26) - 1) << 26);
    }

    #[test]
    fn round_trip_through_string() {
        let original: FlagSet = "+oxv".parse().unwrap();
        let rendered = original.to_string();
        let parsed: FlagSet = rendered.parse().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn display_canonicalizes_letter_order() {
        let set: FlagSet = "+xvo".parse().unwrap();
        assert_eq!(set.to_string(), "+ovx");
    }

    #[test]
    fn empty_flagset_displays_as_empty_string() {
        assert_eq!(FlagSet::NONE.to_string(), "");
    }

    #[test]
    fn diff_with_minus_removes_letters() {
        let mut set: FlagSet = "+oxv".parse().unwrap();
        set.apply_diff("-x").unwrap();
        assert_eq!(set.to_string(), "+ov");
    }

    #[test]
    fn diff_with_plus_then_minus_in_same_string() {
        let mut set = FlagSet::NONE;
        set.apply_diff("+ox-d+v").unwrap();
        assert_eq!(set.to_string(), "+ovx");
    }

    #[test]
    fn invalid_char_rejected() {
        let err = "+!".parse::<FlagSet>().unwrap_err();
        assert_eq!(err, FlagSetParseError::InvalidChar('!'));
    }

    #[test]
    fn contains_letter_checks_membership() {
        let set: FlagSet = "+ox".parse().unwrap();
        assert!(set.contains_letter('o'));
        assert!(set.contains_letter('x'));
        assert!(!set.contains_letter('v'));
        assert!(!set.contains_letter('!'));
    }

    #[test]
    fn union_and_difference() {
        let a: FlagSet = "+ox".parse().unwrap();
        let b: FlagSet = "+vx".parse().unwrap();
        assert_eq!((a | b).to_string(), "+ovx");
        assert_eq!(a.difference(b).to_string(), "+o");
        assert_eq!((a & b).to_string(), "+x");
    }

    #[test]
    fn contains_subset() {
        let parent: FlagSet = "+oxv".parse().unwrap();
        let child: FlagSet = "+ov".parse().unwrap();
        assert!(parent.contains(child));
        assert!(!child.contains(parent));
    }

    #[test]
    fn lowercase_o_and_uppercase_o_are_distinct_bits() {
        let lower: FlagSet = "+o".parse().unwrap();
        let upper: FlagSet = "+O".parse().unwrap();
        assert_ne!(lower.bits(), upper.bits());
        assert!(!lower.contains(upper));
    }

    #[test]
    fn letters_iterates_in_canonical_order() {
        let set: FlagSet = "+xZaO".parse().unwrap();
        let collected: String = set.letters().collect();
        assert_eq!(collected, "axOZ");
    }

    #[test]
    fn serde_round_trip_via_json() {
        let set: FlagSet = "+ox".parse().unwrap();
        let j = serde_json::to_string(&set).unwrap();
        let back: FlagSet = serde_json::from_str(&j).unwrap();
        assert_eq!(set, back);
    }

    #[test]
    fn apply_diff_idempotent_on_redundant_adds() {
        let mut set: FlagSet = "+o".parse().unwrap();
        set.apply_diff("+o").unwrap();
        assert_eq!(set.to_string(), "+o");
    }

    #[test]
    fn from_letters_rejects_plus_or_minus() {
        // from_letters does not interpret diff markers — pass clean letters.
        let err = FlagSet::from_letters("+o").unwrap_err();
        assert_eq!(err, FlagSetParseError::InvalidChar('+'));
    }

    #[test]
    fn canonical_letters_match_wraith() {
        // Sanity check the published constants point at the right chars.
        assert_eq!(USER_OP, 'o');
        assert_eq!(USER_AUTOOP, 'O');
        assert_eq!(USER_KICK, 'k');
        assert_eq!(USER_OWNER, 'n');
        assert_eq!(USER_ADMIN, 'a');
    }
}
