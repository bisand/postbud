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
    /// TXT records at the first `_dmarc.` name that had any, of the two
    /// RFC 7489 §6.6.3 defines: the domain itself, then its
    /// organizational domain. A subdomain without its own policy
    /// inherits the organizational one — never an intermediate label's.
    pub dmarc_txt: Vec<String>,
    /// Where the DMARC records were found, when they were.
    pub dmarc_found_at: Option<String>,
    /// MX exchange hosts at the domain.
    pub mx: Vec<String>,
    /// TXT records at each `<domain>._report._dmarc.<rua-host>` name that
    /// [`report_auth_names`] asked for, in the same order. Empty when the
    /// DMARC record names no external report destination — there is then
    /// nothing to authorize.
    pub report_auth: Vec<(String, Vec<String>)>,
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
    /// None when the DMARC record names no external report destination.
    ///
    /// Deliberately NOT part of `valid`: where aggregate reports are sent
    /// has no bearing on whether mail authenticates, and `valid` drives
    /// the recheck cadence. A domain must not be pushed into 15-minute
    /// rechecks forever over a reporting address.
    pub report_auth: Option<RecordResult>,
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
        // Seen in production: a second v=spf1 record is a PermError for
        // the WHOLE domain — even when one of the two is exactly right.
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
    // Seen in production: a record exists, but the key is not the one the
    // relay signs with — every signature fails verification, and the
    // record looks perfectly fine to the eye.
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

/// The registrable domain, approximated as the last two labels — the same
/// approximation [`dmarc_names`] makes, and wrong in the same way for
/// multi-label suffixes like co.uk.
pub fn organizational_domain(domain: &str) -> String {
    let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    if labels.len() <= 2 {
        labels.join(".").to_ascii_lowercase()
    } else {
        labels[labels.len() - 2..].join(".").to_ascii_lowercase()
    }
}

/// The mail domains named by a DMARC record's `rua=` tag.
///
/// `rua=mailto:a@x.example,mailto:b@y.example!10m` yields `x.example` and
/// `y.example`; the `!size` suffix RFC 7489 §6.2 allows is not part of
/// the address.
pub fn rua_domains(record: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tag in record.split(';') {
        let Some((key, value)) = tag.split_once('=') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("rua") {
            continue;
        }
        for uri in value.split(',') {
            let uri = uri.trim();
            if uri.len() < 7 || !uri[..7].eq_ignore_ascii_case("mailto:") {
                continue;
            }
            let addr = &uri[7..];
            let addr = addr.split('!').next().unwrap_or(addr);
            if let Some((_, host)) = addr.rsplit_once('@') {
                let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
                if !host.is_empty() && !out.contains(&host) {
                    out.push(host);
                }
            }
        }
    }
    out
}

/// The `_report._dmarc` names that must exist for a DMARC record's
/// EXTERNAL report destinations (RFC 7489 §7.1).
///
/// Reports to an address in the record's own organizational domain are a
/// domain consenting to itself and need nothing published. Reports to
/// anywhere else need that host to say so, otherwise receivers silently
/// send nothing — no error, no bounce, just an empty inbox that looks
/// exactly like "no mail was sent".
///
/// `publishing_domain` is the domain the record was actually FOUND at,
/// not the domain being checked: an inherited policy is authorized by the
/// parent that published it.
pub fn report_auth_names(publishing_domain: &str, record: &str) -> Vec<String> {
    let org = organizational_domain(publishing_domain);
    rua_domains(record)
        .into_iter()
        .filter(|host| organizational_domain(host) != org)
        .map(|host| format!("{publishing_domain}._report._dmarc.{host}"))
        .collect()
}

/// Every authorization name must answer with a DMARC-version record.
fn check_report_auth(observed: &[(String, Vec<String>)]) -> Option<RecordResult> {
    if observed.is_empty() {
        return None;
    }
    let missing: Vec<&str> = observed
        .iter()
        .filter(|(_, txt)| {
            !txt.iter().any(|t| {
                t.trim_start()
                    .get(..8)
                    .is_some_and(|p| p.eq_ignore_ascii_case("v=DMARC1"))
            })
        })
        .map(|(name, _)| name.as_str())
        .collect();

    Some(if missing.is_empty() {
        RecordResult {
            status: Status::Ok,
            observed: Some(
                observed
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        }
    } else {
        RecordResult {
            status: Status::Missing,
            observed: Some(format!(
                "reports will NOT be sent: {} is missing",
                missing.join(", ")
            )),
        }
    })
}

pub fn evaluate(expected: &Expected, observed: &Observed) -> DomainResult {
    let spf = check_spf(&observed.domain_txt, &expected.spf);
    let dkim = check_dkim(&observed.dkim_txt, &expected.dkim_public_key);
    let dmarc = check_dmarc(&observed.dmarc_txt, observed.dmarc_found_at.as_deref());
    let mx = expected.mx.as_deref().map(|m| check_mx(&observed.mx, m));
    let report_auth = check_report_auth(&observed.report_auth);

    let valid = spf.status == Status::Ok
        && dkim.status == Status::Ok
        && dmarc.status == Status::Ok
        && mx.as_ref().is_none_or(|m| m.status == Status::Ok);

    DomainResult {
        spf,
        dkim,
        dmarc,
        mx,
        report_auth,
        valid,
    }
}

/// The `_dmarc.` names a receiver would try, in order.
///
/// RFC 7489 §6.6.3 is exactly two lookups: the domain itself, then its
/// ORGANIZATIONAL domain. Intermediate labels are never consulted.
///
/// This used to walk every label in between, which cost more than a
/// wasted lookup: for `test.postbud.example` it would find a policy at
/// `_dmarc.postbud.example` and report the domain green against a record
/// no receiver will ever apply to it, while Gmail and Microsoft used the
/// organizational domain's instead. The admin UI showed one record and
/// the world used another.
///
/// The organizational domain is still approximated as the last two
/// labels — see [`organizational_domain`] — so this remains wrong for
/// multi-label suffixes like co.uk. That approximation is unchanged; only
/// the labels between are dropped.
pub fn dmarc_names(domain: &str) -> Vec<String> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let org = organizational_domain(&domain);
    let mut names = vec![format!("_dmarc.{domain}")];
    if org != domain && !org.is_empty() {
        names.push(format!("_dmarc.{org}"));
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
            report_auth: Vec::new(),
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

    /// RFC 7489 §6.6.3: the domain, then the organizational domain. The
    /// labels in between are never consulted, so a policy published at
    /// `_dmarc.sub.example.com` does not apply to `mail.sub.example.com`
    /// and must not be reported as though it did.
    #[test]
    fn dmarc_lookup_skips_intermediate_labels() {
        assert_eq!(
            dmarc_names("mail.sub.example.com"),
            vec![
                "_dmarc.mail.sub.example.com".to_string(),
                "_dmarc.example.com".to_string(),
            ]
        );
        assert_eq!(
            dmarc_names("example.com"),
            vec!["_dmarc.example.com".to_string()]
        );
    }

    #[test]
    fn dmarc_names_normalize_case_and_the_root_dot() {
        assert_eq!(
            dmarc_names("Mail.Example.COM."),
            vec![
                "_dmarc.mail.example.com".to_string(),
                "_dmarc.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn rua_addresses_yield_their_hosts() {
        assert_eq!(
            rua_domains("v=DMARC1; p=none; rua=mailto:a@x.example,mailto:b@y.example!10m"),
            vec!["x.example".to_string(), "y.example".to_string()]
        );
        assert!(rua_domains("v=DMARC1; p=reject").is_empty());
    }

    /// Reporting to your own organizational domain is consent to
    /// yourself: nothing to publish, nothing to check.
    #[test]
    fn a_same_domain_rua_needs_no_authorization() {
        assert!(
            report_auth_names("example.com", "v=DMARC1; p=none; rua=mailto:d@example.com")
                .is_empty()
        );
        assert!(
            report_auth_names(
                "mail.example.com",
                "v=DMARC1; p=none; rua=mailto:d@example.com"
            )
            .is_empty()
        );
    }

    #[test]
    fn an_external_rua_names_the_record_the_other_host_must_publish() {
        assert_eq!(
            report_auth_names(
                "sub.example.com",
                "v=DMARC1; p=none; rua=mailto:d@other.example"
            ),
            vec!["sub.example.com._report._dmarc.other.example".to_string()]
        );
    }

    /// The incident: `rua` was repointed at another domain without that
    /// domain publishing the authorization, and every receiver silently
    /// stopped sending reports. Nothing else in the check notices — the
    /// DMARC record itself is still perfectly valid.
    #[test]
    fn an_unauthorized_external_rua_is_reported_missing() {
        let mut o = all_good();
        o.report_auth = vec![(
            "sub.example.com._report._dmarc.other.example".into(),
            Vec::new(),
        )];
        let r = evaluate(&expected(), &o);
        let auth = r.report_auth.expect("a destination was checked");
        assert_eq!(auth.status, Status::Missing);
        assert!(auth.observed.unwrap().contains("will NOT be sent"));
        // Where reports go says nothing about whether mail authenticates.
        assert!(r.valid);
    }

    #[test]
    fn an_authorized_external_rua_is_ok_and_no_destination_is_none() {
        let mut o = all_good();
        o.report_auth = vec![(
            "sub.example.com._report._dmarc.other.example".into(),
            vec!["v=DMARC1".into()],
        )];
        assert_eq!(
            evaluate(&expected(), &o).report_auth.unwrap().status,
            Status::Ok
        );
        assert!(evaluate(&expected(), &all_good()).report_auth.is_none());
    }
}
