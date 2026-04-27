//! Argon2id password hashing for the admin login flow.
//!
//! `User.password_hash` stores the encoded PHC string produced by
//! [`hash`]. [`verify`] returns `Ok(true)` only on a clean Argon2 match
//! against that string — wrong password is `Ok(false)`, parse failure
//! is `Err`.
//!
//! Default parameters (m=64 MiB, t=3, p=1) are the
//! [OWASP recommendation](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id)
//! and are intentionally on the slower side for an interactive login —
//! Shade's login traffic is operator-rate, not user-rate.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

/// Errors raised while hashing or verifying a password.
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("argon2: {0}")]
    Argon2(String),
    #[error("invalid stored hash: {0}")]
    InvalidHash(String),
}

fn argon2() -> Argon2<'static> {
    // Defaults: m_cost = 64 MiB, t_cost = 3, p_cost = 1, output_len = 32.
    // `Params::new` returns Result; the values below are valid so unwrap
    // is fine.
    let params = Params::new(64 * 1024, 3, 1, None).expect("argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash `password` with Argon2id and a fresh random salt. Returns the
/// encoded PHC string suitable for storage in `User.password_hash`.
pub fn hash(password: &str) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| PasswordError::Argon2(e.to_string()))
}

/// Verify `password` against a previously-hashed PHC string. Returns
/// `Ok(true)` on match, `Ok(false)` on a clean mismatch, and an error
/// only if the stored hash is malformed.
pub fn verify(password: &str, encoded: &str) -> Result<bool, PasswordError> {
    let parsed =
        PasswordHash::new(encoded).map_err(|e| PasswordError::InvalidHash(e.to_string()))?;
    match argon2().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(PasswordError::Argon2(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_matches() {
        let h = hash("correct horse battery staple").unwrap();
        assert!(verify("correct horse battery staple", &h).unwrap());
    }

    #[test]
    fn wrong_password_does_not_match() {
        let h = hash("hunter2").unwrap();
        assert!(!verify("hunter3", &h).unwrap());
    }

    #[test]
    fn fresh_hashes_have_distinct_salts() {
        let a = hash("same").unwrap();
        let b = hash("same").unwrap();
        assert_ne!(a, b, "salt should make repeat hashes differ");
    }

    #[test]
    fn malformed_stored_hash_errors() {
        let err = verify("anything", "not a phc string").unwrap_err();
        assert!(matches!(err, PasswordError::InvalidHash(_)));
    }
}
