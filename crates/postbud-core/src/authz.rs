//! Which tenant may send as which sender.
//!
//! This is the boundary that a shared relay needs and a bare SMTP
//! credential cannot give you: with one SASL login for everything, a leaked
//! key from any product can send as any other. Here every tenant carries an
//! explicit list of domains, and it is checked on every accept.

use crate::address;

/// May this tenant send with this `From:` address?
///
/// Matching is exact on the domain, case-insensitive. Subdomains are
/// deliberately NOT implied: allowing `bogen.tech` must not silently allow
/// `phish.bogen.tech`, and a wildcard is the kind of convenience that turns
/// into an incident. List every sending domain explicitly.
pub fn may_send_as(from: &str, allowed_domains: &[String]) -> bool {
    let Some(domain) = address::domain(from) else {
        return false;
    };
    allowed_domains
        .iter()
        .any(|allowed| allowed.trim().eq_ignore_ascii_case(&domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains() -> Vec<String> {
        vec!["bogen.tech".into(), "faktura.regnmed.no".into()]
    }

    #[test]
    fn listed_domains_are_allowed_case_insensitively() {
        assert!(may_send_as("no-reply@bogen.tech", &domains()));
        assert!(may_send_as("faktura@FAKTURA.REGNMED.NO", &domains()));
    }

    #[test]
    fn an_unlisted_domain_is_refused() {
        assert!(!may_send_as("no-reply@networco.no", &domains()));
    }

    /// The property that makes per-tenant keys worth having: a stolen
    /// regnmed key cannot be used to send as anyone else.
    #[test]
    fn a_subdomain_is_not_implied_by_its_parent() {
        assert!(!may_send_as("no-reply@phish.bogen.tech", &domains()));
    }

    #[test]
    fn a_malformed_sender_is_refused_rather_than_matched() {
        assert!(!may_send_as("no-reply", &domains()));
        assert!(!may_send_as("", &domains()));
    }
}
