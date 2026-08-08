//! API keys.
//!
//! A key is 32 bytes from the OS random source, so it is stored as a plain
//! SHA-256 digest rather than a password hash. That is not a shortcut: a
//! password hash exists to make low-entropy guesses expensive, and there is
//! no guessing 256 bits. What we need instead is a fast, fixed-length
//! digest we can put a unique index on.
//!
//! The key is shown exactly once, at creation. postbud cannot recover it —
//! it does not have it. Losing one means issuing a new one.

use rand::RngCore;
use sha2::{Digest, Sha256};

/// Prefix so a leaked key is recognizable in a log or a paste, the way
/// other services mark theirs.
pub const PREFIX: &str = "pb_live_";

/// Generate a new key. Returned in full, once.
pub fn generate() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{PREFIX}{hex}")
}

/// The digest stored in `tenant.api_key_hash`.
pub fn hash(key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.trim().as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_prefixed_and_unique() {
        let a = generate();
        let b = generate();
        assert!(a.starts_with(PREFIX));
        assert_eq!(a.len(), PREFIX.len() + 64);
        assert_ne!(a, b);
    }

    #[test]
    fn hashing_is_stable_and_ignores_surrounding_whitespace() {
        let key = generate();
        assert_eq!(hash(&key), hash(&format!("  {key}\n")));
    }

    #[test]
    fn different_keys_hash_differently() {
        assert_ne!(hash(&generate()), hash(&generate()));
    }
}
