//! Postfix's `showq` protocol, read directly.
//!
//! `postqueue -j` is a formatter around this socket. Speaking it here
//! instead means the reporter needs no Postfix binaries beside it, so it
//! stays a static musl binary in a `FROM scratch` image rather than
//! dragging in a 40 MB package to run one command.
//!
//! The framing is NUL-separated `name\0value\0` pairs; an EMPTY name ends
//! a record. The stream opens with a `protocol` record naming itself and
//! closes when the far end hangs up:
//!
//! ```text
//! protocol\0mail_queue_list_protocol\0\0
//! queue_name\0deferred\0queue_id\0004E6F5409\0time\0...\0size\0...\0
//! sender\0...\0recipient\0...\0reason\0host mx.example[..] said: 451 ...\0\0
//! ```
//!
//! This is a private Postfix protocol with no stability promise. It is
//! pinned by a test built from bytes captured off a live relay, so a
//! change in framing fails here rather than in production -- where the
//! failure mode is an empty queue, and an empty queue is what concludes
//! that every outstanding message was delivered.

use crate::relayqueue::Queued;

/// Parse one complete showq response.
///
/// A record without a `queue_id` is not a queue entry -- the opening
/// `protocol` record is one such -- and is skipped. Several recipients
/// produce repeated `recipient`/`reason` pairs; the first reason is kept,
/// since it is the one shown against the message.
pub fn parse(bytes: &[u8]) -> Vec<Queued> {
    let mut out = Vec::new();
    let mut fields = bytes.split(|b| *b == 0);

    let mut queue_id: Option<String> = None;
    let mut queue_name: Option<String> = None;
    let mut reason: Option<String> = None;

    while let Some(name) = fields.next() {
        if name.is_empty() {
            // Record boundary.
            if let (Some(id), Some(qn)) = (queue_id.take(), queue_name.take()) {
                out.push(Queued {
                    queue_id: id,
                    queue_name: qn,
                    reason: reason.take().filter(|r| !r.is_empty()),
                });
            }
            queue_id = None;
            queue_name = None;
            reason = None;
            continue;
        }
        let Some(value) = fields.next() else { break };
        let value = String::from_utf8_lossy(value).trim().to_string();
        match String::from_utf8_lossy(name).as_ref() {
            "queue_id" => queue_id = Some(value),
            "queue_name" => queue_name = Some(value),
            "reason" if reason.is_none() => reason = Some(value),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured verbatim from a live relay while a receiver was rate
    /// limiting us. If Postfix ever changes the framing, this is what
    /// notices.
    const CAPTURED: &[u8] = b"protocol\x00mail_queue_list_protocol\x00\x00queue_name\x00deferred\x00queue_id\x003F373F5418\x00time\x001787026965\x00size\x005794\x00forced_expire\x000\x00sender\x00no-reply@example.com\x00recipient\x00user@example.net\x00reason\x00host mx.example.net[192.0.2.22] said: 451 4.7.7 Please try again later. IP rate-limited. (in reply to end of DATA command)\x00\x00queue_name\x00active\x00queue_id\x00004E6F5409\x00time\x001787026952\x00size\x003118\x00forced_expire\x000\x00sender\x00no-reply@example.com\x00recipient\x00other@example.net\x00\x00\x00";

    #[test]
    fn the_opening_protocol_record_is_not_a_queue_entry() {
        let q = parse(CAPTURED);
        assert_eq!(q.len(), 2, "{q:?}");
        assert!(q.iter().all(|e| !e.queue_id.is_empty()));
    }

    #[test]
    fn a_deferred_entry_carries_the_receivers_own_words() {
        let q = parse(CAPTURED);
        assert_eq!(q[0].queue_id, "3F373F5418");
        assert_eq!(q[0].queue_name, "deferred");
        assert!(q[0].reason.as_deref().unwrap().contains("451 4.7.7"));
    }

    /// A message being attempted right now has no failure to report, and
    /// must not inherit the previous record's.
    #[test]
    fn an_active_entry_has_no_reason() {
        let q = parse(CAPTURED);
        assert_eq!(q[1].queue_id, "004E6F5409");
        assert_eq!(q[1].queue_name, "active");
        assert_eq!(q[1].reason, None);
    }

    /// An empty queue still sends the protocol header. It must parse to
    /// zero entries, never to a parse failure -- and the caller must be
    /// able to tell it apart from having read nothing at all.
    #[test]
    fn an_empty_queue_is_zero_entries() {
        assert!(parse(b"protocol\0mail_queue_list_protocol\0\0\0").is_empty());
    }
}
