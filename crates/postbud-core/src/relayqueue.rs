//! Reading Postfix's queue, so a message that never left it stops looking
//! like a delivered one.
//!
//! postbud hands a message to the smarthost, records the queue id, and by
//! design learns nothing more -- Postfix owns delivery. That is still
//! true; nothing here delivers mail. What it does is close the reporting
//! gap that boundary leaves: a destination blocked for two hours produced
//! no bounce (a 4xx never does), so every message sat in the relay's
//! deferred queue while the admin UI showed a clean handoff and no way to
//! tell the difference.
//!
//! The source is `postqueue -j`, one JSON object per line, NOT a JSON
//! array. Parsed here rather than in the shell script that collects it:
//! the relay should hold as little logic as possible, and this way the
//! parsing has tests.

use serde::Deserialize;

/// One message still sitting in the relay's queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queued {
    /// Postfix's queue id -- the same value stored on the message when the
    /// relay accepted it, and the only thing that joins the two.
    pub queue_id: String,
    /// `deferred`, `active`, `hold`, `incoming`, `maildrop`.
    pub queue_name: String,
    /// Why it is still here, in the receiver's own words. None while a
    /// message is merely active and has not failed yet.
    pub reason: Option<String>,
}

#[derive(Deserialize)]
struct RawEntry {
    queue_id: String,
    queue_name: String,
    #[serde(default)]
    recipients: Vec<RawRecipient>,
}

#[derive(Deserialize)]
struct RawRecipient {
    #[serde(default)]
    delay_reason: Option<String>,
}

/// Parse `postqueue -j` output.
///
/// Unparseable lines are skipped rather than failing the batch. A queue
/// report is a snapshot of an operational system: one malformed line must
/// not cost us the state of every other message in it.
pub fn parse(raw: &str) -> Vec<Queued> {
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<RawEntry>(line).ok())
        .map(|e| Queued {
            reason: e
                .recipients
                .iter()
                .find_map(|r| r.delay_reason.clone())
                .map(|r| r.trim().to_string())
                .filter(|r| !r.is_empty()),
            queue_id: e.queue_id,
            queue_name: e.queue_name,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from a live relay while a destination was blocking us.
    const REAL: &str = r#"{"queue_name": "deferred", "queue_id": "3F373F5418", "arrival_time": 1787026965, "message_size": 5794, "forced_expire": false, "sender": "no-reply@example.com", "recipients": [{"address": "user@example.net", "delay_reason": "host mx.example.net[192.0.2.22] said: 451 4.7.7 Please try again later. IP rate-limited. (in reply to end of DATA command)"}]}
{"queue_name": "active", "queue_id": "004E6F5409", "arrival_time": 1787026952, "message_size": 3118, "forced_expire": false, "sender": "no-reply@example.com", "recipients": [{"address": "other@example.net"}]}"#;

    #[test]
    fn a_deferred_entry_carries_the_receivers_own_words() {
        let q = parse(REAL);
        assert_eq!(q.len(), 2);
        assert_eq!(q[0].queue_id, "3F373F5418");
        assert_eq!(q[0].queue_name, "deferred");
        assert!(q[0].reason.as_deref().unwrap().contains("451 4.7.7"));
    }

    /// A message being tried right now has no failure to report yet, and
    /// must not be shown as though it had one.
    #[test]
    fn an_active_entry_has_no_reason() {
        let q = parse(REAL);
        assert_eq!(q[1].queue_name, "active");
        assert_eq!(q[1].reason, None);
    }

    /// An empty queue is the healthy case, not a parse failure.
    #[test]
    fn an_empty_report_is_an_empty_queue() {
        assert!(parse("").is_empty());
        assert!(parse("\n  \n").is_empty());
    }

    /// One bad line must not cost us the rest of the snapshot.
    #[test]
    fn a_malformed_line_is_skipped_not_fatal() {
        let raw = format!("not json at all\n{}", REAL.lines().next().unwrap());
        let q = parse(&raw);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].queue_id, "3F373F5418");
    }
}
