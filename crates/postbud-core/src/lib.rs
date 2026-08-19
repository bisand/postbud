//! Pure delivery policy. No I/O, no database, no network.
//!
//! Everything here is a decision that has to be identical whether it is
//! taken by the API on accept, by the worker on retry, or by the bounce
//! ingester hours later — so it lives in one place and is tested directly.

pub mod address;
pub mod apikey;
pub mod authz;
pub mod dmarc;
pub mod dnscheck;
pub mod dsn;
pub mod rdns;
pub mod relayqueue;
pub mod retry;
pub mod showq;

/// What a delivery attempt or a bounce means for the message.
///
/// The distinction that matters is *permanent vs transient*, because only
/// a permanent failure may add an address to the suppression list. Getting
/// this backwards in either direction is expensive: suppress on a transient
/// failure and a customer silently stops receiving invoices; retry a
/// permanent one and the relay's reputation pays for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// 2xx — the relay accepted the message.
    Accepted,
    /// 4xx, a connection failure, or a timeout. Try again later.
    Transient,
    /// 5xx. Never try again. Whether the address is also suppressed is a
    /// narrower question than this enum answers — see
    /// [`dsn::Report::should_suppress`].
    Permanent,
    /// A bounce we could not read. Never acted on automatically.
    Unknown,
}

impl Classification {
    /// Classify a bare SMTP reply code.
    pub fn from_smtp_code(code: u16) -> Self {
        match code / 100 {
            2 => Classification::Accepted,
            4 => Classification::Transient,
            5 => Classification::Permanent,
            _ => Classification::Unknown,
        }
    }

    /// Classify an RFC 3463 enhanced status code such as `5.1.1`.
    pub fn from_status(status: &str) -> Self {
        match status.trim().split('.').next() {
            Some("2") => Classification::Accepted,
            Some("4") => Classification::Transient,
            Some("5") => Classification::Permanent,
            _ => Classification::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_codes_classify_by_leading_digit() {
        assert_eq!(
            Classification::from_smtp_code(250),
            Classification::Accepted
        );
        assert_eq!(
            Classification::from_smtp_code(421),
            Classification::Transient
        );
        assert_eq!(
            Classification::from_smtp_code(452),
            Classification::Transient
        );
        assert_eq!(
            Classification::from_smtp_code(550),
            Classification::Permanent
        );
        assert_eq!(Classification::from_smtp_code(999), Classification::Unknown);
    }

    #[test]
    fn enhanced_status_codes_classify_by_leading_class() {
        assert_eq!(
            Classification::from_status("5.1.1"),
            Classification::Permanent
        );
        assert_eq!(
            Classification::from_status("4.4.1"),
            Classification::Transient
        );
        assert_eq!(
            Classification::from_status(" 2.0.0 "),
            Classification::Accepted
        );
        assert_eq!(
            Classification::from_status("garbage"),
            Classification::Unknown
        );
    }

    /// A mailbox-full bounce is 4.2.2 and must NOT suppress the address:
    /// the mailbox will very likely be emptied. This is the single most
    /// common way a naive suppression list starts silently dropping a
    /// customer's mail forever.
    #[test]
    fn mailbox_full_is_transient_not_permanent() {
        assert_eq!(
            Classification::from_status("4.2.2"),
            Classification::Transient
        );
    }
}
