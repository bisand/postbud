//! Relay identity evaluation: does the machine mail leaves from say the
//! same thing three different ways?
//!
//! Pure on purpose, like [`crate::dnscheck`] — the caller does the
//! lookups and hands the answers in.
//!
//! Large receivers judge a sending IP on a three-way agreement, and any
//! one of them missing is enough to be greylisted or scored down:
//!
//! 1. the host resolves forward to the address mail comes from;
//! 2. that address resolves BACK to the same host (the PTR);
//! 3. the SMTP greeting announces that host too.
//!
//! Two and three are the ones that rot silently. A provider hands out a
//! generic PTR (`static-198-51-100-7.example-isp.net`) unless asked, and
//! a relay rebuilt from a fresh image announces `localhost.localdomain`
//! until someone sets `myhostname`. Neither breaks a test send — they
//! cost reputation slowly, at the receivers that matter most.

use crate::dnscheck::{RecordResult, Status};

/// What the caller observed. Addresses and names arrive already
/// lowercased and stripped of any trailing dot.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    /// A/AAAA addresses the relay host resolves to.
    pub forward_ips: Vec<String>,
    /// PTR names found for those addresses.
    pub ptr_names: Vec<String>,
    /// Hostname the relay announced in its SMTP greeting, when we could
    /// read one. `None` means we could not connect — an outage, which
    /// must not be recorded as a misconfiguration.
    pub banner_host: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RelayResult {
    pub forward: RecordResult,
    pub ptr: RecordResult,
    /// `None` when the greeting could not be read at all.
    pub helo: Option<RecordResult>,
    pub valid: bool,
}

/// Compare two host names as DNS does: case-insensitively, ignoring the
/// root dot that a resolver may or may not include.
fn same_host(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

pub fn evaluate(expected_host: &str, observed: &Observed) -> RelayResult {
    let forward = if observed.forward_ips.is_empty() {
        RecordResult {
            status: Status::Missing,
            observed: None,
        }
    } else {
        RecordResult {
            status: Status::Ok,
            observed: Some(observed.forward_ips.join(", ")),
        }
    };

    let ptr = match observed.ptr_names.len() {
        0 => RecordResult {
            status: Status::Missing,
            // Named rather than left blank: "no PTR" is the single most
            // common reason a self-hosted relay is refused outright, and
            // the fix is a request to the address's owner, not a DNS
            // record anyone here can add.
            observed: Some("no PTR — the address's owner must set it".into()),
        },
        _ => {
            let matched = observed
                .ptr_names
                .iter()
                .any(|name| same_host(name, expected_host));
            let seen = observed.ptr_names.join(", ");
            if matched {
                RecordResult {
                    status: Status::Ok,
                    // Several PTRs is legal and forward-confirmed as long
                    // as one matches, but a receiver may show any of them,
                    // so the others stay visible rather than being hidden
                    // behind an "ok".
                    observed: Some(seen),
                }
            } else {
                RecordResult {
                    status: Status::Mismatch,
                    observed: Some(seen),
                }
            }
        }
    };

    // Absent greeting = unknown, never a failure. The relay being down is
    // our problem, and recording it as "the relay is misconfigured" would
    // be a lie that outlives the outage in the check history.
    let helo = observed.banner_host.as_ref().map(|banner| {
        if same_host(banner, expected_host) {
            RecordResult {
                status: Status::Ok,
                observed: Some(banner.clone()),
            }
        } else {
            RecordResult {
                status: Status::Mismatch,
                observed: Some(banner.clone()),
            }
        }
    });

    let valid = forward.status == Status::Ok
        && ptr.status == Status::Ok
        && helo.as_ref().is_none_or(|h| h.status == Status::Ok);

    RelayResult {
        forward,
        ptr,
        helo,
        valid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(ips: &[&str], ptrs: &[&str], banner: Option<&str>) -> Observed {
        Observed {
            forward_ips: ips.iter().map(|s| s.to_string()).collect(),
            ptr_names: ptrs.iter().map(|s| s.to_string()).collect(),
            banner_host: banner.map(|s| s.to_string()),
        }
    }

    #[test]
    fn a_fully_aligned_relay_is_valid() {
        let result = evaluate(
            "postbud.bogentech.no",
            &observed(
                &["85.137.228.199"],
                &["postbud.bogentech.no"],
                Some("postbud.bogentech.no"),
            ),
        );
        assert!(result.valid);
        assert_eq!(result.ptr.status, Status::Ok);
        assert_eq!(result.helo.unwrap().status, Status::Ok);
    }

    /// The state this relay was actually in until the address's owner set
    /// the record. Everything else was already correct, which is exactly
    /// why it needs saying out loud.
    #[test]
    fn a_missing_ptr_is_reported_as_missing_not_as_a_mismatch() {
        let result = evaluate(
            "postbud.bogentech.no",
            &observed(&["85.137.228.199"], &[], Some("postbud.bogentech.no")),
        );
        assert!(!result.valid);
        assert_eq!(result.ptr.status, Status::Missing);
        assert!(result.ptr.observed.unwrap().contains("owner"));
    }

    /// What a provider hands out when nobody asks: it resolves, it looks
    /// like a hostname, and it fails every receiver's forward-confirmation.
    #[test]
    fn a_generic_provider_ptr_is_a_mismatch() {
        let result = evaluate(
            "postbud.bogentech.no",
            &observed(
                &["85.137.228.199"],
                &["static-85-137-228-199.example-isp.net"],
                Some("postbud.bogentech.no"),
            ),
        );
        assert!(!result.valid);
        assert_eq!(result.ptr.status, Status::Mismatch);
    }

    /// A relay rebuilt from a fresh image announces this until someone
    /// sets myhostname. DNS is perfect; the greeting is not, and the
    /// three-way match is what receivers test.
    #[test]
    fn a_default_helo_fails_even_when_dns_is_right() {
        let result = evaluate(
            "postbud.bogentech.no",
            &observed(
                &["85.137.228.199"],
                &["postbud.bogentech.no"],
                Some("localhost.localdomain"),
            ),
        );
        assert!(!result.valid);
        assert_eq!(result.helo.unwrap().status, Status::Mismatch);
    }

    /// An unreachable relay is OUR outage. Recording it as a failed
    /// identity would put a lie in the history that outlives the outage.
    #[test]
    fn an_unreadable_greeting_is_unknown_rather_than_failed() {
        let result = evaluate(
            "postbud.bogentech.no",
            &observed(&["85.137.228.199"], &["postbud.bogentech.no"], None),
        );
        assert!(
            result.valid,
            "DNS is correct; the greeting is merely unknown"
        );
        assert!(result.helo.is_none());
    }

    #[test]
    fn names_compare_ignoring_case_and_the_root_dot() {
        let result = evaluate(
            "postbud.bogentech.no",
            &observed(
                &["85.137.228.199"],
                &["Postbud.BogenTech.No."],
                Some("POSTBUD.bogentech.no"),
            ),
        );
        assert!(result.valid);
    }

    #[test]
    fn a_host_that_resolves_nowhere_is_missing() {
        let result = evaluate("postbud.bogentech.no", &observed(&[], &[], None));
        assert!(!result.valid);
        assert_eq!(result.forward.status, Status::Missing);
    }

    /// Legal, and forward-confirmed as long as one matches — but the
    /// others stay visible, because a receiver may show any of them.
    #[test]
    fn several_ptrs_pass_when_one_matches_and_the_rest_stay_visible() {
        let result = evaluate(
            "postbud.bogentech.no",
            &observed(
                &["85.137.228.199"],
                &["postbud.bogentech.no", "old-name.example.net"],
                Some("postbud.bogentech.no"),
            ),
        );
        assert!(result.valid);
        assert!(
            result
                .ptr
                .observed
                .unwrap()
                .contains("old-name.example.net")
        );
    }
}
