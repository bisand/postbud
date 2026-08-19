//! Delivery Status Notification parsing (RFC 3464).
//!
//! Hand-rolled and tolerant: a bounce we cannot read is stored raw and
//! reported, never discarded and never guessed at. An unparsed bounce is a
//! bug report.
//!
//! The field that matters most is `X-Postfix-Queue-ID` in the
//! `message/delivery-status` part. It is easy to assume that is the queue
//! id of the *bounce* — it is not. Postfix puts the ORIGINAL message's
//! queue id there, which is exactly the value the relay handed back to us
//! in its `250 Ok: queued as ...` response. That single field is what joins
//! a bounce arriving on Thursday to an invoice sent on Monday.

use crate::Classification;

/// One recipient's outcome within a DSN. A single bounce may carry several.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The queue id of the message that failed, if the DSN carried one.
    pub relay_queue_id: Option<String>,
    /// `Final-Recipient`, with the `rfc822;` prefix stripped.
    pub final_recipient: Option<String>,
    /// `Status`, e.g. `5.1.1`.
    pub status: Option<String>,
    /// `Diagnostic-Code`, the remote MTA's own words. Worth keeping
    /// verbatim: it is what you paste into a support ticket.
    pub diagnostic: Option<String>,
    pub classification: Classification,
}

impl Report {
    /// Only a permanent failure *about this recipient* may suppress an
    /// address. Anything else — including a bounce we could not classify —
    /// leaves the address alone.
    ///
    /// Permanence alone is not enough, and reading it as enough is the
    /// expensive mistake here. A `5.7.1` is permanent in the only sense
    /// retrying cares about: the receiver will refuse it again tomorrow.
    /// But it says the receiver rejected the MESSAGE — for DMARC policy,
    /// for our reputation, for its own rules — and says nothing at all
    /// about whether the mailbox exists. A sending domain at `p=reject`
    /// whose SPF and DKIM both break earns one of these for every message
    /// it sends, each one naming a recipient who is perfectly fine.
    /// Suppressing on that would take every address mailed during an
    /// outage on OUR side out of service, globally, for every tenant, and
    /// only a human lifting them one at a time puts it back.
    pub fn should_suppress(&self) -> bool {
        if self.classification != Classification::Permanent {
            return false;
        }
        // The code first, the receiver's own words second. Both must sit
        // behind the permanence check: a 4.x.x saying "user unknown" is a
        // receiver contradicting itself, and the safe reading of a
        // contradiction is the one that keeps writing to the address.
        self.status.as_deref().is_some_and(recipient_is_the_problem)
            || self
                .diagnostic
                .as_deref()
                .is_some_and(names_a_missing_mailbox)
    }
}

/// Does an RFC 3463 enhanced status blame the recipient's address?
///
/// Deliberately an allowlist: a code we do not recognise must not cost an
/// address. The subject sub-code carries the signal — `.1` is addressing
/// and `.2` is the mailbox, while `.3` (system), `.4` (network), `.5`
/// (protocol), `.6` (content) and `.7` (security/policy) all describe
/// something that happened around the message rather than a mailbox that
/// is gone. Within the two that can qualify, the exclusions matter as much
/// as the rule:
///
/// - `5.1.7` and `5.1.8` name the SENDER's address, not the recipient's.
/// - `5.2.2` is a full mailbox: the permanent spelling of the `4.2.2` that
///   must never suppress. Full mailboxes get emptied.
/// - `5.2.3` is a message too large for the mailbox, which is evidence the
///   mailbox is there and working.
/// - `5.0.0` and `5.1.0` mean "something else went wrong". A code carrying
///   no information must not be read as bad news about the address.
fn recipient_is_the_problem(status: &str) -> bool {
    let Some((_class, subject_and_detail)) = status.trim().split_once('.') else {
        return false;
    };
    matches!(
        subject_and_detail,
        // No such mailbox; no such domain; an address that cannot be
        // parsed; a mailbox moved away leaving no forwarding; a domain
        // publishing a null MX to say it receives no mail at all; and a
        // mailbox the receiver reports as disabled for good.
        "1.1" | "1.2" | "1.3" | "1.6" | "1.10" | "2.1"
    )
}

/// Phrases in which a receiver says, in its own words, that the mailbox is
/// not there.
///
/// The enhanced status code is the primary signal and stays an allowlist.
/// This exists because that code is not always the truth. Sendmail-derived
/// servers answer a nonexistent mailbox with `553 5.3.0 ... No such user
/// here` — filing a dead address under MAIL SYSTEM, a class where nothing
/// may suppress and nothing should. Found against a real receiver, on a
/// real address that would otherwise have been mailed forever.
///
/// Deliberately short and deliberately unambiguous. Every phrase names the
/// RECIPIENT as missing, and none of them can be produced by a full
/// mailbox, a policy rejection or a broken relay. "does not exist" is
/// absent on purpose: a domain that does not exist says it too, and so
/// does an account that is merely disabled.
const MISSING_MAILBOX: [&str; 5] = [
    "no such user",
    "user unknown",
    "recipient not found",
    "mailbox not found",
    "no mailbox here",
];

fn names_a_missing_mailbox(diagnostic: &str) -> bool {
    // Folded headers arrive joined but not normalised, so the spacing a
    // receiver used must not decide whether an address survives.
    let flat = diagnostic
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    MISSING_MAILBOX.iter().any(|phrase| flat.contains(phrase))
}

/// Parse a raw DSN. Returns one [`Report`] per recipient block found.
///
/// An empty result means "we could not read this", which the caller stores
/// as an unparsed bounce rather than treating as "nothing was wrong".
pub fn parse(raw: &str) -> Vec<Report> {
    let mut reports = Vec::new();
    // Per-message fields appear once, before the recipient blocks, and
    // apply to all of them.
    let mut queue_id: Option<String> = None;
    let mut current: Option<Report> = None;

    for line in unfold(raw) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if value.is_empty() {
            continue;
        }

        match name.as_str() {
            "x-postfix-queue-id" => queue_id = Some(value),
            // A Final-Recipient line starts a new recipient block.
            "final-recipient" => {
                if let Some(report) = current.take() {
                    reports.push(report);
                }
                current = Some(Report {
                    relay_queue_id: queue_id.clone(),
                    final_recipient: Some(strip_type_prefix(&value)),
                    status: None,
                    diagnostic: None,
                    classification: Classification::Unknown,
                });
            }
            "status" => {
                if let Some(report) = current.as_mut() {
                    report.classification = Classification::from_status(&value);
                    report.status = Some(value);
                }
            }
            "diagnostic-code" => {
                if let Some(report) = current.as_mut() {
                    report.diagnostic = Some(strip_type_prefix(&value));
                }
            }
            _ => {}
        }
    }

    if let Some(report) = current.take() {
        reports.push(report);
    }

    // The queue id may appear after the first Final-Recipient in some
    // layouts; backfill rather than lose the join key.
    if let Some(id) = queue_id {
        for report in &mut reports {
            report.relay_queue_id.get_or_insert_with(|| id.clone());
        }
    }

    reports
}

/// Join RFC 5322 folded continuation lines (a line starting with space or
/// tab continues the one before it) so field parsing sees whole values.
fn unfold(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in raw.lines() {
        if line.starts_with([' ', '\t']) && !out.is_empty() {
            let last = out.last_mut().expect("checked non-empty");
            last.push(' ');
            last.push_str(line.trim());
        } else {
            out.push(line.to_string());
        }
    }
    out
}

/// `rfc822; user@example.com` and `smtp; 550 ...` both carry a type prefix
/// that is noise for our purposes.
fn strip_type_prefix(value: &str) -> String {
    match value.split_once(';') {
        Some((_, rest)) => rest.trim().to_string(),
        None => value.trim().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real Postfix hard bounce, trimmed to the reporting parts.
    const HARD_BOUNCE: &str = "\
Content-Type: message/delivery-status

Reporting-MTA: dns; mail.example.org
X-Postfix-Queue-ID: 4bXlNq2Qh8z1Yk
X-Postfix-Sender: rfc822; no-reply@example.org
Arrival-Date: Thu, 7 Aug 2026 09:14:02 +0200 (CEST)

Final-Recipient: rfc822; nosuch@example.com
Original-Recipient: rfc822;nosuch@example.com
Action: failed
Status: 5.1.1
Remote-MTA: dns; mx.example.com
Diagnostic-Code: smtp; 550 5.1.1 <nosuch@example.com>: Recipient address
    rejected: User unknown in local recipient table
";

    /// What Postfix returns when a message outlives
    /// `maximal_queue_lifetime`. Note the contradiction it carries: RFC
    /// 3464 defines `Action: failed` as permanent, while the enhanced
    /// status is 4.x, which is transient.
    const EXPIRY_BOUNCE: &str = "\
Content-Type: message/delivery-status

Reporting-MTA: dns; mail.example.org
X-Postfix-Queue-ID: 08785F9FED

Final-Recipient: rfc822; user@example.net
Action: failed
Status: 4.4.7
Diagnostic-Code: X-Postfix; delivery time expired
";

    /// The status must win over the action.
    ///
    /// A destination that blocked us for four days is not a dead mailbox,
    /// and suppressing on this would take a working address out of
    /// service globally because someone else's network was down. Reading
    /// `Action: failed` as authoritative is the obvious mistake here, and
    /// this is what stops it being made later.
    #[test]
    fn an_expired_queue_entry_never_suppresses() {
        let reports = parse(EXPIRY_BOUNCE);
        assert_eq!(reports.len(), 1);
        let r = &reports[0];
        assert_eq!(r.relay_queue_id.as_deref(), Some("08785F9FED"));
        assert_eq!(r.status.as_deref(), Some("4.4.7"));
        assert_eq!(r.classification, Classification::Transient);
        assert!(!r.should_suppress());
    }

    #[test]
    fn a_hard_bounce_yields_the_queue_id_and_suppresses() {
        let reports = parse(HARD_BOUNCE);
        assert_eq!(reports.len(), 1);
        let r = &reports[0];
        assert_eq!(r.relay_queue_id.as_deref(), Some("4bXlNq2Qh8z1Yk"));
        assert_eq!(r.final_recipient.as_deref(), Some("nosuch@example.com"));
        assert_eq!(r.status.as_deref(), Some("5.1.1"));
        assert_eq!(r.classification, Classification::Permanent);
        assert!(r.should_suppress());
    }

    /// The folded Diagnostic-Code must come back as one string — it is the
    /// text a human reads when asking why a customer never got an invoice.
    #[test]
    fn folded_diagnostic_lines_are_joined() {
        let reports = parse(HARD_BOUNCE);
        let diagnostic = reports[0].diagnostic.as_deref().unwrap();
        assert!(diagnostic.ends_with("User unknown in local recipient table"));
        assert!(!diagnostic.contains('\n'));
    }

    #[test]
    fn a_deferred_report_does_not_suppress() {
        let raw = "X-Postfix-Queue-ID: ABC123\n\
                   Final-Recipient: rfc822; busy@example.com\n\
                   Action: delayed\n\
                   Status: 4.2.2\n";
        let reports = parse(raw);
        assert_eq!(reports[0].classification, Classification::Transient);
        assert!(!reports[0].should_suppress());
    }

    /// One failed report carrying `status`, for the tables below.
    fn one_report(status: &str) -> Report {
        let raw = format!(
            "X-Postfix-Queue-ID: TESTQ\n\
             Final-Recipient: rfc822; recipient@example.com\n\
             Action: failed\n\
             Status: {status}\n"
        );
        parse(&raw).into_iter().next().expect("one report")
    }

    /// A policy rejection is permanent and still must not suppress.
    ///
    /// This is the shape of a DMARC `p=reject` refusal — including
    /// Google's `5.7.26` for a message that aligned on neither SPF nor
    /// DKIM. Every one of these is caused by our own authentication
    /// breaking, and every one of them names a recipient who is fine.
    /// Suppressing here empties a working address list over an outage the
    /// recipient had no part in.
    #[test]
    fn a_policy_rejection_never_suppresses() {
        for status in ["5.7.0", "5.7.1", "5.7.9", "5.7.26"] {
            let r = one_report(status);
            assert_eq!(r.classification, Classification::Permanent);
            assert!(!r.should_suppress(), "{status} must not suppress");
        }
    }

    /// The codes that really do mean the mailbox is gone keep suppressing.
    /// Narrowing the rule must not quietly disable the feature.
    #[test]
    fn a_dead_address_still_suppresses() {
        for status in ["5.1.1", "5.1.2", "5.1.3", "5.1.6", "5.1.10", "5.2.1"] {
            let r = one_report(status);
            assert!(r.should_suppress(), "{status} must suppress");
        }
    }

    /// The case that put this rule here, verbatim from production.
    ///
    /// Domeneshop runs a sendmail-derived server, which answers a
    /// nonexistent mailbox with `553 5.3.0 ... No such user here`. The
    /// code files it under MAIL SYSTEM, where nothing may suppress; only
    /// the words say what actually happened. Without this the address is
    /// mailed forever and the relay's reputation pays for it.
    #[test]
    fn a_dead_mailbox_suppresses_on_the_receivers_words() {
        let raw = "X-Postfix-Queue-ID: B3F1716F856\n\
                   Final-Recipient: rfc822; nobody@example.com\n\
                   Action: failed\n\
                   Status: 5.3.0\n\
                   Diagnostic-Code: smtp; 553 5.3.0 <nobody@example.com>... \
                   No such user here\n";
        let r = &parse(raw)[0];
        assert_eq!(r.status.as_deref(), Some("5.3.0"));
        assert!(r.should_suppress(), "the words name a missing mailbox");
    }

    #[test]
    fn the_wording_is_matched_whatever_the_case_and_spacing() {
        for text in [
            "550 USER UNKNOWN",
            "550 Recipient  not   found",
            "550 Mailbox not found",
            "550 no mailbox here by that name",
        ] {
            let raw = format!(
                "Final-Recipient: rfc822; nobody@example.com\n\
                 Status: 5.0.0\n\
                 Diagnostic-Code: smtp; {text}\n"
            );
            assert!(parse(&raw)[0].should_suppress(), "{text} must suppress");
        }
    }

    /// A 5.3.0 that really is a mail-system failure must stay untouched:
    /// the point of the phrase list is that it names the RECIPIENT, and a
    /// full disk at the far end says nothing about who was written to.
    #[test]
    fn a_real_system_failure_still_never_suppresses() {
        for text in [
            "452 4.3.1 Insufficient system storage",
            "550 5.3.0 Mail system rejected the message",
            "550 5.7.1 Message rejected due to policy",
            "550 5.2.2 Mailbox full",
        ] {
            let raw = format!(
                "Final-Recipient: rfc822; nobody@example.com\n\
                 Status: 5.3.0\n\
                 Diagnostic-Code: smtp; {text}\n"
            );
            assert!(
                !parse(&raw)[0].should_suppress(),
                "{text} must not suppress"
            );
        }
    }

    /// The words never outrank permanence. A receiver that defers while
    /// saying "user unknown" is contradicting itself, and the safe reading
    /// of a contradiction keeps writing to the address.
    #[test]
    fn a_transient_failure_is_not_rescued_by_its_wording() {
        let raw = "Final-Recipient: rfc822; nobody@example.com\n\
                   Status: 4.2.0\n\
                   Diagnostic-Code: smtp; 450 no such user, try later\n";
        assert!(!parse(raw)[0].should_suppress());
    }

    /// Permanent, but not about the address: a full mailbox gets emptied,
    /// an oversized message gets sent again smaller, a broken network gets
    /// fixed, and a bare `5.0.0` tells us nothing whatsoever.
    #[test]
    fn a_permanent_failure_that_is_not_the_address_never_suppresses() {
        for status in [
            "5.0.0", "5.1.0", "5.1.7", "5.1.8", "5.2.2", "5.2.3", "5.3.0", "5.4.4", "5.5.2",
            "5.6.1",
        ] {
            let r = one_report(status);
            assert_eq!(r.classification, Classification::Permanent);
            assert!(!r.should_suppress(), "{status} must not suppress");
        }
    }

    #[test]
    fn several_recipients_produce_several_reports_sharing_the_queue_id() {
        let raw = "X-Postfix-Queue-ID: QQQ\n\
                   Final-Recipient: rfc822; a@example.com\n\
                   Status: 5.1.1\n\
                   \n\
                   Final-Recipient: rfc822; b@example.com\n\
                   Status: 4.4.1\n";
        let reports = parse(raw);
        assert_eq!(reports.len(), 2);
        assert!(
            reports
                .iter()
                .all(|r| r.relay_queue_id.as_deref() == Some("QQQ"))
        );
        assert_eq!(reports[0].classification, Classification::Permanent);
        assert_eq!(reports[1].classification, Classification::Transient);
    }

    /// Nothing recognizable must produce nothing — never a fabricated
    /// "everything was fine", and never a suppression.
    #[test]
    fn unreadable_input_yields_no_reports() {
        assert!(parse("this is not a bounce at all").is_empty());
        assert!(parse("").is_empty());
    }
}
