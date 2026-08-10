//! Domain-verification evaluation: given what DNS actually said, decide
//! whether a sending domain authenticates.
//!
//! Pure on purpose — the caller (the worker) does the lookups and hands
//! the answers in, so every rule here is unit-testable without a
//! resolver. The rules encode two failures that really happened, not
//! hypotheticals:
//!
//! * TWO SPF records on one name is a PermError (RFC 7208 §4.5): every
//!   receiver treats the domain as having no valid SPF at all. Reported
//!   as `mismatch` with an explanation, never as "one of them matched".
//! * A published DKIM record whose key is not the relay's signing key
//!   verifies nothing — it looks fine to the eye and fails at every
//!   receiver. The check compares the key material itself.

/// What DNS answered, fetched by the caller. TXT records arrive with
/// their character-string chunks already concatenated per record (the
/// wire format splits long records at 255 bytes; that split is
/// presentation, not content).
#[derive(Debug, Clone, Default)]
pub struct Observed {
    /// TXT records at the domain apex.
    pub domain_txt: Vec<String>,
    /// TXT records at `<selector>._domainkey.<domain>`.
    pub dkim_txt: Vec<String>,
    /// TXT records at the nearest `_dmarc.` name that had any, walking
    /// from `_dmarc.<domain>` toward the organizational domain — DMARC
    /// §6.6.3: a subdomain without its own policy inherits.
    pub dmarc_txt: Vec<String>,
    /// Where the DMARC records were found, when they were.
    pub dmarc_found_at: Option<String>,
    /// MX exchange hosts at the domain.
    pub mx: Vec<String>,
}

/// What DNS is supposed to say, from the sending-domain registry.
#[derive(Debug, Clone)]
pub struct Expected {
    pub spf: String,
    pub dkim_public_key: String,
    /// None = the domain is not required to route bounces.
    pub mx: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Missing,
    Mismatch,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Missing => "missing",
            Status::Mismatch => "mismatch",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecordResult {
    pub status: Status,
    /// What was actually seen — shown in the UI so a mismatch is
    /// diagnosable without a terminal.
    pub observed: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DomainResult {
    pub spf: RecordResult,
    pub dkim: RecordResult,
    pub dmarc: RecordResult,
    /// None when no MX is expected.
    pub mx: Option<RecordResult>,
    pub valid: bool,
}

/// Collapse whitespace so cosmetic differences (double spaces, tabs,
/// trailing space) don't fail a semantically identical record.
fn normalize_spaces(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn check_spf(observed: &[String], expected: &str) -> RecordResult {
    let spf: Vec<&String> = observed
        .iter()
        .filter(|t| {
            let t = t.trim_start();
            t.len() >= 6 && t[..6].eq_ignore_ascii_case("v=spf1")
        })
        .collect();

    match spf.len() {
        0 => RecordResult {
            status: Status::Missing,
            observed: None,
        },
        1 => {
            let seen = normalize_spaces(spf[0]);
            if seen.eq_ignore_ascii_case(&normalize_spaces(expected)) {
                RecordResult {
                    status: Status::Ok,
                    observed: Some(seen),
                }
            } else {
                RecordResult {
                    status: Status::Mismatch,
                    observed: Some(seen),
                }
            }
        }
        // The regnmed.no incident: a second v=spf1 record is a PermError
        // for the WHOLE domain — even if one of them is the right one.
        n => RecordResult {
            status: Status::Mismatch,
            observed: Some(format!(
                "{n} SPF records — RFC 7208 PermError; receivers treat the domain as having none"
            )),
        },
    }
}

/// Pull the `p=` value out of a DKIM TXT record and strip the base64 of
/// anything cosmetic.
fn dkim_key_of(record: &str) -> Option<String> {
    record.split(';').find_map(|tag| {
        let tag = tag.trim();
        tag.strip_prefix("p=").map(|v| {
            v.chars()
                .filter(|c| !c.is_whitespace() && *c != '"')
                .collect()
        })
    })
}

fn check_dkim(observed: &[String], expected_key: &str) -> RecordResult {
    if observed.is_empty() {
        return RecordResult {
            status: Status::Missing,
            observed: None,
        };
    }
    let expected: String = expected_key
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '"')
        .collect();

    for record in observed {
        if let Some(key) = dkim_key_of(record)
            && key == expected
        {
            return RecordResult {
                status: Status::Ok,
                observed: Some("published key matches the signing key".into()),
            };
        }
    }
    // The postbud.networco.no incident: a record exists, the key is not
    // the one the relay signs with — every signature fails verification.
    RecordResult {
        status: Status::Mismatch,
        observed: Some("a DKIM record exists but its key is NOT the relay's signing key".into()),
    }
}

fn check_dmarc(observed: &[String], found_at: Option<&str>) -> RecordResult {
    let dmarc = observed.iter().find(|t| {
        let t = t.trim_start();
        t.len() >= 8 && t[..8].eq_ignore_ascii_case("v=DMARC1")
    });
    match dmarc {
        Some(record) => RecordResult {
            status: Status::Ok,
            observed: Some(match found_at {
                Some(name) => format!("{} (at {name})", normalize_spaces(record)),
                None => normalize_spaces(record),
            }),
        },
        None => RecordResult {
            status: Status::Missing,
            observed: None,
        },
    }
}

fn normalize_host(h: &str) -> String {
    h.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn check_mx(observed: &[String], expected: &str) -> RecordResult {
    if observed.is_empty() {
        return RecordResult {
            status: Status::Missing,
            observed: None,
        };
    }
    let want = normalize_host(expected);
    if observed.iter().any(|h| normalize_host(h) == want) {
        RecordResult {
            status: Status::Ok,
            observed: Some(observed.join(", ")),
        }
    } else {
        RecordResult {
            status: Status::Mismatch,
            observed: Some(observed.join(", ")),
        }
    }
}

pub fn evaluate(expected: &Expected, observed: &Observed) -> DomainResult {
    let spf = check_spf(&observed.domain_txt, &expected.spf);
    let dkim = check_dkim(&observed.dkim_txt, &expected.dkim_public_key);
    let dmarc = check_dmarc(&observed.dmarc_txt, observed.dmarc_found_at.as_deref());
    let mx = expected.mx.as_deref().map(|m| check_mx(&observed.mx, m));

    let valid = spf.status == Status::Ok
        && dkim.status == Status::Ok
        && dmarc.status == Status::Ok
        && mx.as_ref().is_none_or(|m| m.status == Status::Ok);

    DomainResult {
        spf,
        dkim,
        dmarc,
        mx,
        valid,
    }
}

/// The `_dmarc.` names to try, nearest first — DMARC inheritance without
/// a public-suffix list: walk toward the registrable domain and stop
/// while at least two labels remain. Wrong for multi-label suffixes like
/// co.uk (it would try one name too many, which merely wastes a lookup),
/// right for the common case.
pub fn dmarc_names(domain: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut labels: Vec<&str> = domain.split('.').collect();
    while labels.len() >= 2 {
        names.push(format!("_dmarc.{}", labels.join(".")));
        labels.remove(0);
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected() -> Expected {
        Expected {
            spf: "v=spf1 ip4:192.0.2.10 -all".into(),
            dkim_public_key: "MIIBIjANBgkqAAAA".into(),
            mx: Some("mail.example.com".into()),
        }
    }

    fn all_good() -> Observed {
        Observed {
            domain_txt: vec!["v=spf1 ip4:192.0.2.10 -all".into()],
            dkim_txt: vec!["v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqAAAA".into()],
            dmarc_txt: vec!["v=DMARC1; p=none".into()],
            dmarc_found_at: Some("_dmarc.sub.example.com".into()),
            mx: vec!["mail.example.com.".into()],
        }
    }

    #[test]
    fn a_fully_published_domain_is_valid() {
        let r = evaluate(&expected(), &all_good());
        assert!(r.valid, "{r:?}");
    }

    /// The incident this exists for: a second SPF record is a PermError
    /// even when one of the two is exactly right.
    #[test]
    fn duplicate_spf_is_a_mismatch_even_if_one_matches() {
        let mut o = all_good();
        o.domain_txt
            .push("v=spf1 include:other.example ~all".into());
        let r = evaluate(&expected(), &o);
        assert_eq!(r.spf.status, Status::Mismatch);
        assert!(r.spf.observed.unwrap().contains("PermError"));
        assert!(!r.valid);
    }

    /// The other incident: a DKIM record that exists but carries a key
    /// the relay does not sign with.
    #[test]
    fn wrong_dkim_key_is_a_mismatch_not_ok() {
        let mut o = all_good();
        o.dkim_txt = vec!["v=DKIM1; k=rsa; p=SOMEOTHERKEY".into()];
        let r = evaluate(&expected(), &o);
        assert_eq!(r.dkim.status, Status::Mismatch);
        assert!(!r.valid);
    }

    /// Long DKIM keys arrive split into quoted chunks; the fetcher joins
    /// them, but stray quotes and spaces must not fail the comparison.
    #[test]
    fn dkim_comparison_survives_chunking_artifacts() {
        let mut o = all_good();
        o.dkim_txt = vec!["v=DKIM1; k=rsa; p=MIIBIjANB\" \"gkqAAAA".into()];
        let r = evaluate(&expected(), &o);
        assert_eq!(r.dkim.status, Status::Ok);
    }

    #[test]
    fn unrelated_txt_records_do_not_disturb_spf() {
        let mut o = all_good();
        o.domain_txt.insert(0, "brevo-code:abc123".into());
        o.domain_txt.push("google-site-verification=xyz".into());
        let r = evaluate(&expected(), &o);
        assert_eq!(r.spf.status, Status::Ok);
    }

    #[test]
    fn missing_records_report_missing() {
        let o = Observed::default();
        let r = evaluate(&expected(), &o);
        assert_eq!(r.spf.status, Status::Missing);
        assert_eq!(r.dkim.status, Status::Missing);
        assert_eq!(r.dmarc.status, Status::Missing);
        assert_eq!(r.mx.unwrap().status, Status::Missing);
        assert!(!r.valid);
    }

    #[test]
    fn a_domain_without_expected_mx_ignores_mx() {
        let mut e = expected();
        e.mx = None;
        let mut o = all_good();
        o.mx.clear();
        let r = evaluate(&e, &o);
        assert!(r.mx.is_none());
        assert!(r.valid);
    }

    #[test]
    fn mx_matching_ignores_case_and_trailing_dot() {
        let mut o = all_good();
        o.mx = vec!["MAIL.EXAMPLE.COM".into()];
        let r = evaluate(&expected(), &o);
        assert_eq!(r.mx.unwrap().status, Status::Ok);
    }

    #[test]
    fn dmarc_walk_up_names_stop_at_the_registrable_domain() {
        assert_eq!(
            dmarc_names("postbud.networco.no"),
            vec![
                "_dmarc.postbud.networco.no".to_string(),
                "_dmarc.networco.no".to_string(),
            ]
        );
        assert_eq!(
            dmarc_names("example.com"),
            vec!["_dmarc.example.com".to_string()]
        );
    }
}
