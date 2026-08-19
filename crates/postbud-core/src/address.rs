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

/// The envelope sender to hand the relay for a message from `mail_from`.
///
/// A DSN comes back to the ENVELOPE sender, never to the `From:` header,
/// and a mail library will derive the envelope from `From:` unless it is
/// told otherwise. That default is quietly wrong for us: the `From:`
/// address is the one a person replies to, so it is usually aliased to a
/// human mailbox, and every bounce then lands in somebody's inbox instead
/// of the ingest pipe. Nothing breaks visibly. The mail still arrives, to
/// the wrong reader, and the suppression list simply never learns
/// anything.
///
/// The mailbox keeps the SENDER's domain on purpose. SPF is evaluated
/// against the envelope domain, so an envelope in the same domain leaves
/// alignment exactly as it was; one shared bounce domain across tenants
/// would have to be authorized and aligned on its own, and would put every
/// tenant's return path behind one name.
///
/// `None` when no sensible address can be formed — a caller that asked for
/// this and got nothing has a bug to surface, not a default to fall back
/// on.
pub fn bounce_sender(mail_from: &str, mailbox: &str) -> Option<String> {
    let mailbox = mailbox.trim();
    if mailbox.is_empty() || mailbox.chars().any(|c| c == '@' || c.is_whitespace()) {
        return None;
    }
    Some(format!("{mailbox}@{}", domain(mail_from)?))
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

#[cfg(test)]
mod bounce_tests {
    use super::*;

    /// The domain must follow the sender, because SPF is checked against
    /// the envelope domain and alignment must not move.
    #[test]
    fn the_bounce_sender_keeps_the_senders_domain() {
        assert_eq!(
            bounce_sender("no-reply@mail.example.com", "bounces").as_deref(),
            Some("bounces@mail.example.com")
        );
        assert_eq!(
            bounce_sender("Invoices@Example.COM", "bounces").as_deref(),
            Some("bounces@example.com")
        );
    }

    #[test]
    fn a_mailbox_may_be_named_anything_sane() {
        assert_eq!(
            bounce_sender("x@example.com", "  return-path  ").as_deref(),
            Some("return-path@example.com")
        );
    }

    /// Refused rather than mangled: a mailbox carrying its own `@` would
    /// build a nonsense address, and an empty one would build `@domain`.
    #[test]
    fn a_mailbox_that_is_not_a_local_part_yields_nothing() {
        assert_eq!(bounce_sender("x@example.com", ""), None);
        assert_eq!(bounce_sender("x@example.com", "   "), None);
        assert_eq!(
            bounce_sender("x@example.com", "bounces@other.example"),
            None
        );
        assert_eq!(bounce_sender("x@example.com", "two words"), None);
    }

    #[test]
    fn a_sender_without_a_domain_yields_nothing() {
        assert_eq!(bounce_sender("not-an-address", "bounces"), None);
        assert_eq!(bounce_sender("", "bounces"), None);
    }
}
