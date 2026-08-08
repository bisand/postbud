//! Address handling.
//!
//! Deliberately shallow: this is not an RFC 5321 validator, and pretending
//! otherwise would be worse than useless. It rejects the shapes that are
//! certainly wrong (no `@`, empty parts, whitespace, a domain without a
//! dot) and leaves the real verdict to the receiving MTA, which is the
//! only party that actually knows.

/// Normalize for storage and comparison: trim, and lowercase the domain.
///
/// The local part is left alone. It is case-sensitive per the RFC, and
/// while practically every provider treats it case-insensitively, silently
/// rewriting the part of the address the recipient chose is not our call.
/// Suppression lookups lowercase both sides in SQL instead.
pub fn normalize(raw: &str) -> Result<String, AddressError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AddressError::Empty);
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(AddressError::Whitespace);
    }
    // Split on the LAST '@': quoted local parts may legally contain one.
    let (local, domain) = trimmed.rsplit_once('@').ok_or(AddressError::NoAt)?;
    if local.is_empty() || domain.is_empty() {
        return Err(AddressError::EmptyPart);
    }
    if !domain.contains('.') {
        return Err(AddressError::BareDomain);
    }
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

/// The domain part, lowercased. Input is assumed to have passed
/// [`normalize`]; anything else yields `None`.
pub fn domain(address: &str) -> Option<String> {
    address
        .rsplit_once('@')
        .map(|(_, d)| d.to_ascii_lowercase())
        .filter(|d| !d.is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    Empty,
    Whitespace,
    NoAt,
    EmptyPart,
    BareDomain,
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            AddressError::Empty => "address is empty",
            AddressError::Whitespace => "address contains whitespace",
            AddressError::NoAt => "address has no '@'",
            AddressError::EmptyPart => "address has an empty local part or domain",
            AddressError::BareDomain => "domain has no dot",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for AddressError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_is_lowercased_and_local_part_is_not() {
        assert_eq!(
            normalize(" Ola.Nordmann@Example.NO ").unwrap(),
            "Ola.Nordmann@example.no"
        );
    }

    #[test]
    fn obvious_nonsense_is_rejected() {
        assert_eq!(normalize(""), Err(AddressError::Empty));
        assert_eq!(normalize("nobody"), Err(AddressError::NoAt));
        assert_eq!(normalize("@example.no"), Err(AddressError::EmptyPart));
        assert_eq!(normalize("nobody@"), Err(AddressError::EmptyPart));
        assert_eq!(normalize("nobody@localhost"), Err(AddressError::BareDomain));
        assert_eq!(normalize("a b@example.no"), Err(AddressError::Whitespace));
    }

    /// A quoted local part may contain '@', so the split has to be on the
    /// last one. Splitting on the first would send this to the domain
    /// "b@example.no", which does not exist.
    #[test]
    fn splits_on_the_last_at() {
        assert_eq!(
            normalize("\"a@b\"@example.no").unwrap(),
            "\"a@b\"@example.no"
        );
        assert_eq!(domain("\"a@b\"@example.no").as_deref(), Some("example.no"));
    }
}
