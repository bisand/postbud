//! Delivery Status Notification parsing (RFC 3464).
//!
//! Hand-rolled, and tolerant in the same way regnmed's camt.053 and EHF
//! importers are: a bounce we cannot read is stored raw and reported, never
//! discarded and never guessed at. An unparsed bounce is a bug report.
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
    /// Only a permanent failure may suppress an address. Anything else —
    /// including a bounce we could not classify — leaves the address alone.
    pub fn should_suppress(&self) -> bool {
        self.classification == Classification::Permanent
    }
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

Reporting-MTA: dns; mail.bogentech.no
X-Postfix-Queue-ID: 4bXlNq2Qh8z1Yk
X-Postfix-Sender: rfc822; no-reply@bogen.tech
Arrival-Date: Thu, 7 Aug 2026 09:14:02 +0200 (CEST)

Final-Recipient: rfc822; nosuch@example.com
Original-Recipient: rfc822;nosuch@example.com
Action: failed
Status: 5.1.1
Remote-MTA: dns; mx.example.com
Diagnostic-Code: smtp; 550 5.1.1 <nosuch@example.com>: Recipient address
    rejected: User unknown in local recipient table
";

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
